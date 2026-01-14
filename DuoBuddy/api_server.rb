require 'webrick'
require 'json'
require 'securerandom'
require 'openssl'

# Monkey patch to allow ProcHandler to handle OPTIONS requests
class WEBrick::HTTPServlet::ProcHandler
  def do_OPTIONS(req, res)
    @proc.call(req, res)
  end
end

PORT = (ENV['PORT'] || '5050').to_i
ALLOWED_ORIGINS = ['http://localhost:8000','http://127.0.0.1:8000','https://duobuddy.my','http://duobuddy.my']
DATA_DIR = File.join(__dir__, 'data')
USERS_FILE = File.join(DATA_DIR, 'users.json')
PRODUCTS_FILE = File.join(DATA_DIR, 'products.json')
COMPANIES_FILE = File.join(DATA_DIR, 'companies.json')
COMPANY_ORDERS_FILE = File.join(DATA_DIR, 'company_orders.json')

SESSIONS = {}
LOGIN_ATTEMPTS = {}

def ensure_data
  Dir.mkdir(DATA_DIR) unless Dir.exist?(DATA_DIR)
  unless File.exist?(USERS_FILE)
    admin = create_user_object({
      name: 'Administrator',
      email: 'admin@duobuddy.my',
      username: 'systemadmin',
      phone: '+60 12-000 0000',
      password: 'Admin@123!',
      is_admin: true,
      role: 'super_admin',
      data: { jobTitle: 'Administrator', company: 'DuoBuddy', about: 'System Administrator', created: Time.now.iso8601 }
    })
    File.write(USERS_FILE, JSON.pretty_generate([admin]))
  end
  unless File.exist?(PRODUCTS_FILE)
    products = [
      { 'id' => 'p1', 'name' => 'Black Matte Card', 'stock' => 100, 'available' => true },
      { 'id' => 'p2', 'name' => 'Gold Brushed Card', 'stock' => 100, 'available' => true },
      { 'id' => 'p3', 'name' => 'Silver Brushed Card', 'stock' => 100, 'available' => true }
    ]
    File.write(PRODUCTS_FILE, JSON.pretty_generate(products))
  end
  unless File.exist?(COMPANIES_FILE)
    File.write(COMPANIES_FILE, JSON.pretty_generate([]))
  end
  unless File.exist?(COMPANY_ORDERS_FILE)
    File.write(COMPANY_ORDERS_FILE, JSON.pretty_generate([]))
  end
end

def read_users
  ensure_data
  JSON.parse(File.read(USERS_FILE))
rescue
  []
end

def read_products
  ensure_data
  JSON.parse(File.read(PRODUCTS_FILE))
rescue
  []
end

def read_companies
  ensure_data
  JSON.parse(File.read(COMPANIES_FILE))
rescue
  []
end

def read_company_orders
  ensure_data
  JSON.parse(File.read(COMPANY_ORDERS_FILE))
rescue
  []
end

def write_products(products)
  File.write(PRODUCTS_FILE, JSON.pretty_generate(products))
end

def write_users(users)
  File.write(USERS_FILE, JSON.pretty_generate(users))
end

def write_companies(companies)
  File.write(COMPANIES_FILE, JSON.pretty_generate(companies))
end

def write_company_orders(orders)
  File.write(COMPANY_ORDERS_FILE, JSON.pretty_generate(orders))
end

def hash_password(password, salt=nil)
  salt ||= SecureRandom.hex(16)
  digest = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 100_000, 32, 'sha256').unpack1('H*')
  { 'salt' => salt, 'hash' => digest }
end

def create_user_object(fields)
  hp = hash_password(fields[:password])
  {
    '__backendId' => SecureRandom.hex(8),
    'name' => fields[:name],
    'email' => fields[:email],
    'username' => fields[:username],
    'phone' => fields[:phone],
    'is_admin' => !!fields[:is_admin],
    'role' => fields[:role] || (fields[:is_admin] ? 'super_admin' : 'user'),
    'company_id' => fields[:company_id],
    'passwordSalt' => hp['salt'],
    'passwordHash' => hp['hash'],
    'deleted' => false,
    'data' => (fields[:data].is_a?(String) ? fields[:data] : JSON.dump(fields[:data] || { created: Time.now.iso8601, cards: [] }))
  }
end

def sanitize_user(u)
  u.reject { |k,_| ['passwordHash','passwordSalt'].include?(k) }
end

def set_cors(req, res)
  origin = req.header['origin']&.first
  puts "Request Origin: #{origin.inspect}"
  allowed = ALLOWED_ORIGINS.include?(origin) ? origin : ALLOWED_ORIGINS.first
  res['Access-Control-Allow-Origin'] = allowed
  res['Access-Control-Allow-Credentials'] = 'true'
  res['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, Accept, Origin'
  res['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, HEAD'
end

def set_json(res)
  res['Content-Type'] = 'application/json'
end

def parse_body(req)
  begin
    JSON.parse(req.body || '{}')
  rescue
    {}
  end
end

class CorsProcHandler < WEBrick::HTTPServlet::AbstractServlet
  def initialize(server, proc)
    super(server, proc)
    @proc = proc
  end
  def do_GET(req, res); @proc.call(req, res); end
  def do_POST(req, res); @proc.call(req, res); end
  def do_OPTIONS(req, res); @proc.call(req, res); end
  def do_PUT(req, res); @proc.call(req, res); end
  def do_DELETE(req, res); @proc.call(req, res); end
  alias do_HEAD do_GET
end

def mount_api(server, dir, proc=nil, &block)
  proc ||= block
  server.mount(dir, CorsProcHandler, proc)
end

server = WEBrick::HTTPServer.new(Port: PORT, AccessLog: [], Logger: WEBrick::Log::new($stdout, WEBrick::Log::INFO))

# Serve main app file explicitly and redirect root to DuoBuddy.html to avoid index.html mismatch
mount_api server, '/' do |req, res|
  if req.path == '/' || req.path.empty?
    res.status = 302
    res['Location'] = '/index.html'
  else
    spa_paths = %r{^/(login|signup|admin|company-management|my-cards|profile|edit-profile|change-password)$}
    profile_path = %r{^/profile/[^/]+$}
    company_path = %r{^/company/[^/]+$}
    if req.path =~ spa_paths || req.path =~ profile_path || req.path =~ company_path
      index = File.join(Dir.pwd, 'index.html')
      res['Content-Type'] = 'text/html'
      res.body = File.file?(index) ? File.binread(index) : '<!doctype html><html><body>Index not found</body></html>'
    else
      # For any other static path, attempt to read and serve the file
      path = File.join(Dir.pwd, req.path.sub(/^\//, ''))
      if File.file?(path)
        res['Content-Type'] = WEBrick::HTTPUtils.mime_type(path, WEBrick::HTTPUtils::DefaultMimeTypes)
        res.body = File.binread(path)
      else
        res.status = 404
        res['Content-Type'] = 'text/plain'
        res.body = 'Not Found'
      end
    end
  end
end

def valid_password?(pwd)
  return false if pwd.nil? || pwd.strip.length < 6
  banned = %w[123456 654321 1234567 7654321 password qwerty 123 abc123]
  return false if banned.include?(pwd.downcase)
  true
end

mount_api server, '/api/auth/signup' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  body = parse_body(req)
  name,email,username,password,phone = body.values_at('name','email','username','password','phone')
  if [name,email,username,password].any? { |v| v.to_s.strip.empty? }
    res.status = 400; res.body = { error: 'invalid' }.to_json; next
  end
  unless valid_password?(password)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  users = read_users
  if users.any? { |u| u['email'] == email || u['username'].to_s.downcase == username.to_s.downcase }
    res.status = 409; res.body = { error: 'exists' }.to_json; next
  end
  now = Time.now
  trial_end = (now + 24*60*60).iso8601
  user = create_user_object({ name: name, email: email, username: username, phone: phone, password: password, is_admin: false, data: { jobTitle: '', company: '', about: '', created: now.iso8601, trialEnd: trial_end, cards: [] } })
  users << user
  write_users(users)
  res.body = { ok: true }.to_json
end

mount_api server, '/api/auth/login' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  begin
    ip = (req.respond_to?(:remote_ip) && req.remote_ip) || (req.peeraddr && req.peeraddr[3]) || 'unknown'
    now = Time.now.to_i
    st = LOGIN_ATTEMPTS[ip] || { count: 0, window: now }
    if now - st[:window] > 300
      st = { count: 0, window: now }
    end
    if st[:count] >= 10
      res.status = 429; res.body = { error: 'too_many_attempts' }.to_json; next
    end
    st[:count] += 1
    LOGIN_ATTEMPTS[ip] = st
  rescue
  end
  body = parse_body(req)
  email,password = body.values_at('email','password')
  users = read_users
  user = users.find { |u| u['email'].to_s.downcase == email.to_s.downcase }
  unless user
    res.status = 401; res.body = { error: 'invalid' }.to_json; next
  end
  hp = hash_password(password, user['passwordSalt'])
  if hp['hash'] != user['passwordHash']
    res.status = 401; res.body = { error: 'invalid' }.to_json; next
  end
  sid = SecureRandom.hex(16)
  SESSIONS[sid] = user['__backendId']
  origin = req.header['origin']&.first
  secure = origin && origin.start_with?('https://')
  res['Set-Cookie'] = "sid=#{sid}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax#{secure ? '; Secure' : ''}"
  res.body = { user: sanitize_user(user) }.to_json
end

mount_api server, '/api/auth/logout' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  SESSIONS.delete(sid) if sid
  origin = req.header['origin']&.first
  secure = origin && origin.start_with?('https://')
  res['Set-Cookie'] = "sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax#{secure ? '; Secure' : ''}"
  res.body = { ok: true }.to_json
end

mount_api server, '/api/auth/register-company' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  body = parse_body(req)
  comp_name, comp_reg, industry, comp_address, comp_email, comp_phone = body.values_at('companyName', 'registrationNumber', 'industry', 'address', 'companyEmail', 'companyPhone')
  auth_name, auth_email, password = body.values_at('authPersonName', 'authPersonEmail', 'password')
  
  if [comp_name, comp_email, auth_name, auth_email, password].any? { |v| v.to_s.strip.empty? }
    res.status = 400; res.body = { error: 'missing_fields' }.to_json; next
  end
  
  unless valid_password?(password)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  
  users = read_users
  companies = read_companies
  
  if users.any? { |u| u['email'] == auth_email }
    res.status = 409; res.body = { error: 'email_exists' }.to_json; next
  end
  
  if companies.any? { |c| c['email'] == comp_email || c['registrationNumber'] == comp_reg }
     res.status = 409; res.body = { error: 'company_exists' }.to_json; next
  end
  
  company_id = SecureRandom.hex(8)
  now = Time.now.iso8601
  
  new_company = {
    'id' => company_id,
    'name' => comp_name,
    'registrationNumber' => comp_reg,
    'industry' => industry,
    'address' => comp_address,
    'email' => comp_email,
    'phone' => comp_phone,
    'contactPerson' => auth_name,
    'status' => 'active', # or 'trial'
    'createdAt' => now
  }
  
  # Create Company Admin User
  username = auth_email.split('@').first + '_' + SecureRandom.hex(4)
  admin_user = create_user_object({
    name: auth_name,
    email: auth_email,
    username: username,
    phone: comp_phone,
    password: password,
    is_admin: false,
    role: 'company_admin',
    company_id: company_id,
    data: { jobTitle: 'Company Admin', company: comp_name, about: 'Company Administrator', created: now, cards: [] }
  })
  
  companies << new_company
  users << admin_user
  
  write_companies(companies)
  write_users(users)
  
  res.body = { ok: true, companyId: company_id }.to_json
end

mount_api server, '/api/company/dashboard' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  
  unless user && user['role'] == 'company_admin'
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  
  company_id = user['company_id']
  companies = read_companies
  company = companies.find { |c| c['id'] == company_id }
  
  unless company
     res.status = 404; res.body = { error: 'company_not_found' }.to_json; next
  end
  
  employees = users.select { |u| u['company_id'] == company_id }
  total_cards = employees.reduce(0) { |sum, u| 
    data = JSON.parse(u['data']) rescue {}
    sum + (data['cards'] || []).length
  }
  
  orders = read_company_orders.select { |o| o['companyId'] == company_id }
  
  pending_approvals = orders.count { |o| o['status'] == 'pending_approval' }
  
  res.body = {
    company: company,
    stats: {
      totalEmployees: employees.length,
      totalCards: total_cards,
      pendingApprovals: pending_approvals,
      trialUsers: 0
    },
    orders: orders
  }.to_json
end

mount_api server, '/api/company/employees' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  
  unless user && user['role'] == 'company_admin'
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  
  if req.request_method == 'GET'
    employees = users.select { |u| u['company_id'] == user['company_id'] }.map { |u| sanitize_user(u) }
    res.body = { employees: employees }.to_json
    
  elsif req.request_method == 'POST'
    body = parse_body(req)
    name, email, job_title = body.values_at('name', 'email', 'jobTitle')
    
    if [name, email].any? { |v| v.to_s.strip.empty? }
      res.status = 400; res.body = { error: 'missing_fields' }.to_json; next
    end
    
    if users.any? { |u| u['email'] == email }
       res.status = 409; res.body = { error: 'email_exists' }.to_json; next
    end
    
    # Auto-generate credentials
    username = email.split('@').first + rand(1000..9999).to_s
    temp_password = SecureRandom.hex(4) # In real app, email this
    
    new_employee = create_user_object({
      name: name,
      email: email,
      username: username,
      phone: body['phone'],
      password: temp_password,
      is_admin: false,
      role: 'employee',
      company_id: user['company_id'],
      data: { jobTitle: job_title, company: JSON.parse(user['data'])['company'], about: '', created: Time.now.iso8601, cards: [] }
    })
    
    users << new_employee
    write_users(users)
    
    res.body = { ok: true, employee: sanitize_user(new_employee), tempPassword: temp_password }.to_json
  end
end

mount_api server, '/api/company/orders' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  
  unless user && user['role'] == 'company_admin'
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  
  if req.request_method == 'GET'
     orders = read_company_orders.select { |o| o['companyId'] == user['company_id'] }
     res.body = { orders: orders }.to_json
  elsif req.request_method == 'POST'
     body = parse_body(req)
     quantity = body['quantity'].to_i
     design = body['design']
     
     if quantity < 1
       res.status = 400; res.body = { error: 'invalid_quantity' }.to_json; next
     end
     
     new_order = {
       'id' => SecureRandom.hex(6),
       'companyId' => user['company_id'],
       'quantity' => quantity,
       'design' => design,
       'status' => 'pending_payment',
       'createdAt' => Time.now.iso8601,
       'totalAmount' => quantity * 99 # Hardcoded price
     }
     
     orders = read_company_orders
     orders << new_order
     write_company_orders(orders)
     
     res.body = { ok: true, order: new_order }.to_json
  end
end

mount_api server, '/api/company/orders/payment' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  
  unless user && user['role'] == 'company_admin'
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end

  if req.request_method == 'POST'
    body = parse_body(req)
    order_id = body['orderId']
    receipt_url = body['receiptUrl']
    
    if !order_id || !receipt_url
       res.status = 400; res.body = { error: 'missing_fields' }.to_json; next
    end
    
    orders = read_company_orders
    order = orders.find { |o| o['id'] == order_id && o['companyId'] == user['company_id'] }
    
    unless order
       res.status = 404; res.body = { error: 'order_not_found' }.to_json; next
    end
    
    order['paymentReceipt'] = receipt_url
    order['status'] = 'pending_approval'
    order['paymentDate'] = Time.now.iso8601
    
    write_company_orders(orders)
    
    res.body = { ok: true, order: order }.to_json
  end
end

mount_api server, '/api/bulk_orders' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  if req.request_method == 'POST'
    body = parse_body(req)
    
    # In a real app, this would save to a database or send an email.
    # For this MVP, we'll just log it to stdout or a file if needed.
    # We could reuse the company_orders file if we wanted to track them there,
    # but these are "requests" often from non-users or pre-sales.
    
    # Let's create a bulk_orders.json file to track them.
    bulk_file = File.join(DATA_DIR, 'bulk_orders.json')
    bulk_orders = []
    if File.exist?(bulk_file)
      bulk_orders = JSON.parse(File.read(bulk_file)) rescue []
    end
    
    new_request = {
      'id' => SecureRandom.hex(6),
      'companyName' => body['companyName'],
      'contactPerson' => body['contactPerson'],
      'email' => body['email'],
      'phone' => body['phone'],
      'quantity' => body['quantity'],
      'message' => body['message'],
      'createdAt' => Time.now.iso8601,
      'status' => 'new'
    }
    
    bulk_orders << new_request
    File.write(bulk_file, JSON.pretty_generate(bulk_orders))
    
    res.body = { ok: true, message: 'Request received' }.to_json
  end
end

# Auth: change password
mount_api server, '/api/auth/change_password' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  unless user
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  current = body['currentPassword'].to_s
  new_pwd = body['newPassword'].to_s
  hp = hash_password(current, user['passwordSalt'])
  if hp['hash'] != user['passwordHash']
    res.status = 400; res.body = { error: 'invalid_current' }.to_json; next
  end
  unless valid_password?(new_pwd)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  nh = hash_password(new_pwd)
  user['passwordSalt'] = nh['salt']
  user['passwordHash'] = nh['hash']
  write_users(users)
  res.body = { ok: true }.to_json
end

mount_api server, '/api/users/me' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  res.body = { user: user ? sanitize_user(user) : nil }.to_json
end

mount_api server, '/api/profile' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  # /api/profile/<username>
  username = req.path.sub('/api/profile/', '')
  users = read_users
  user = users.find { |u| u['username'] && u['username'].downcase == username.downcase }
  if !user || user['deleted']
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  res.body = { user: sanitize_user(user) }.to_json
end

mount_api server, '/api/cards/order' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  unless uid
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  slot,design,quantity,address,notes,paymentProof,designImage,qrType,qrText,showPhoneOnCard,nameText,phoneText = body.values_at('slot','design','quantity','address','notes','paymentProof','designImage','qrType','qrText','showPhoneOnCard','nameText','phoneText')
  users = read_users
  user = users.find { |u| u['__backendId'] == uid }
  profile = user['data'] ? JSON.parse(user['data']) : {}
  cards = profile['cards'] || []
  card = cards.find { |c| c['slot'] == slot }
  
  # Stock Logic
  if paymentProof && !paymentProof.to_s.strip.empty?
    products = read_products
    new_product = products.find { |p| p['name'] == design }
    
    if new_product
      if !new_product['available']
        res.status = 400; res.body = { error: 'product_unavailable' }.to_json; next
      end
      
      old_status = card ? card['status'] : nil
      old_design = card ? card['design'] : nil
      
      should_deduct = false
      should_increment_old = false
      old_product = nil
      
      if !old_status || old_status == 'draft'
        should_deduct = true
      elsif ['pending_approval', 'active'].include?(old_status)
        if old_design != design
          should_deduct = true
          should_increment_old = true
          old_product = products.find { |p| p['name'] == old_design }
        end
      end
      
      if should_deduct
        if new_product['stock'] < 1
           res.status = 400; res.body = { error: 'out_of_stock' }.to_json; next
        end
        new_product['stock'] -= 1
      end
      
      if should_increment_old && old_product
        old_product['stock'] += 1
      end
      
      write_products(products) if should_deduct || should_increment_old
    end
  end

  now = Time.now.iso8601
  if card
    card['ordered'] = false
    card['design'] = design
    card['quantity'] = quantity
    card['orderDate'] = now
    card['paymentProof'] = paymentProof
    card['address'] = address
    card['notes'] = notes
    card['status'] = 'pending_approval'
    card['designImage'] = designImage if designImage
    card['qrType'] = qrType if qrType
    card['qrText'] = qrText if qrText
    card['showPhoneOnCard'] = !!showPhoneOnCard
    card['nameText'] = nameText if nameText
    card['phoneText'] = phoneText if phoneText
  else
    cards << { 'slot' => slot, 'ordered' => false, 'design' => design, 'quantity' => quantity, 'orderDate' => now, 'paymentProof' => paymentProof, 'address' => address, 'notes' => notes, 'status' => 'pending_approval', 'designImage' => designImage, 'qrType' => qrType, 'qrText' => qrText, 'showPhoneOnCard' => !!showPhoneOnCard, 'nameText' => nameText, 'phoneText' => phoneText }
  end
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { user: sanitize_user(user) }.to_json
end

 
# Admin: list users (purge deleted > 7 days)
mount_api server, '/api/admin/users' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  # purge
  now = Time.now
  pruned = users.reject do |u|
    if u['deleted'] && u['deletedAt']
      begin
        del = Time.parse(u['deletedAt'])
        (now - del) > (7*24*60*60)
      rescue
        false
      end
    else
      false
    end
  end
  write_users(pruned) if pruned.length != users.length
  res.body = { users: pruned.map { |u| sanitize_user(u) } }.to_json
end

# Admin: delete user (soft)
mount_api server, '/api/admin/delete' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  user['deleted'] = true
  user['deletedAt'] = Time.now.iso8601
  write_users(users)
  res.body = { ok: true }.to_json
end

# Admin: restore user
mount_api server, '/api/admin/restore' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  user['deleted'] = false
  user['deletedAt'] = nil
  write_users(users)
  res.body = { ok: true }.to_json
end

# Admin: approve payment
mount_api server, '/api/admin/approve' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id'] || body['userId']
  slot = body['slot']
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  profile = user['data'] ? JSON.parse(user['data']) : {}
  profile['paymentApproved'] = true
  cards = profile['cards'] || []
  card = cards.find { |c| c['slot'] == slot }
  if card
    card['ordered'] = true
    card['status'] = 'active'
    card['nfcSerial'] = body['nfcSerial'] if body['nfcSerial']
    card['nfcPassword'] = body['nfcPassword'] if body['nfcPassword']
    card['designImage'] = body['designImage'] if body['designImage']
  end
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { ok: true, user: sanitize_user(user) }.to_json
end

# Admin: list all company orders
mount_api server, '/api/admin/company_orders' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  admin = uid && users.find { |u| u['__backendId'] == uid }
  
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  
  orders = read_company_orders
  companies = read_companies
  
  # Enrich orders with company name
  orders.each do |o|
    c = companies.find { |cp| cp['id'] == o['companyId'] }
    o['companyName'] = c ? c['name'] : 'Unknown'
  end
  
  res.body = { orders: orders }.to_json
end

# Admin: approve company order
mount_api server, '/api/admin/company_orders/approve' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  admin = uid && users.find { |u| u['__backendId'] == uid }
  
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  
  body = parse_body(req)
  order_id = body['orderId']
  action = body['action'] # 'approve' or 'reject'
  
  orders = read_company_orders
  order = orders.find { |o| o['id'] == order_id }
  
  unless order
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  
  if action == 'approve'
    order['status'] = 'paid'
    # Here we could also trigger adding credits/slots to the company account if we had that logic
  elsif action == 'reject'
    order['status'] = 'rejected'
  else
    res.status = 400; res.body = { error: 'invalid_action' }.to_json; next
  end
  
  write_company_orders(orders)
  res.body = { ok: true, order: order }.to_json
end

# Admin: delete a user's card slot (reset order)
mount_api server, '/api/admin/delete_card' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  user_id = body['user_id']
  slot = body['slot']
  user = users.find { |u| u['__backendId'] == user_id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  profile = user['data'] ? JSON.parse(user['data']) : {}
  cards = profile['cards'] || []
  cards = cards.reject { |c| c['slot'] == slot }
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { ok: true }.to_json
end

# Admin: approve user profile (e.g., sub-admin confirmation)
mount_api server, '/api/admin/approve_profile' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  user_id = body['user_id']
  user = users.find { |u| u['__backendId'] == user_id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  profile = user['data'] ? JSON.parse(user['data']) : {}
  profile['profileApproved'] = true
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { ok: true }.to_json
end

# Admin: create/update a user's card slot
mount_api server, '/api/admin/create_card' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  user_id = body['user_id']
  slot = body['slot']
  design = body['design']
  name_text = body['nameText']
  phone_text = body['phoneText']
  qr_type = body['qrType']
  qr_text = body['qrText']
  show_phone = !!body['showPhoneOnCard']
  design_image = body['designImage']
  user = users.find { |u| u['__backendId'] == user_id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  profile = user['data'] ? JSON.parse(user['data']) : {}
  cards = profile['cards'] || []
  cards = cards.reject { |c| c['slot'] == slot }
  new_card = {
    'slot' => slot,
    'design' => design,
    'nameText' => name_text,
    'phoneText' => phone_text,
    'qrType' => qr_type,
    'qrText' => qr_text,
    'showPhoneOnCard' => show_phone,
    'designImage' => design_image,
    'createdAt' => Time.now.iso8601
  }
  cards << new_card
  profile['cards'] = cards
  user['data'] = JSON.dump(profile)
  write_users(users)
  res.body = { ok: true }.to_json
end
# Admin: change login email
mount_api server, '/api/admin/email' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  new_email = body['email']&.strip
  if !new_email || new_email.empty?
    res.status = 400; res.body = { error: 'invalid' }.to_json; next
  end
  if users.any? { |u| u['email'].to_s.downcase == new_email.downcase && u['__backendId'] != id }
    res.status = 409; res.body = { error: 'exists' }.to_json; next
  end
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  user['email'] = new_email
  write_users(users)
  res.body = { ok: true, user: sanitize_user(user) }.to_json
end

# Admin: get products
mount_api server, '/api/admin/products' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  res.body = { products: read_products }.to_json
end

# Admin: update product
mount_api server, '/api/admin/products/update' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  stock = body['stock']
  available = body['available']
  
  products = read_products
  product = products.find { |p| p['id'] == id }
  if product
    product['stock'] = stock.to_i if stock
    product['available'] = available unless available.nil?
    write_products(products)
    res.body = { ok: true }.to_json
  else
    res.status = 404; res.body = { error: 'not_found' }.to_json
  end
end

# Public: get products list
mount_api server, '/api/products' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  users = read_users
  uid = sid && SESSIONS[sid]
  user = uid && users.find { |u| u['__backendId'] == uid }
  is_admin = user && (user['is_admin'] || user['is_subadmin'])

  products = read_products
  
  unless is_admin
    # Hide stock count for non-admins
    products = products.map do |p|
      p_clone = p.dup
      p_clone['stock'] = p_clone['stock'] > 0 ? 'Available' : 'Out of Stock'
      p_clone
    end
  end
  
  res.body = { products: products }.to_json
end

# Admin: reset user password
mount_api server, '/api/admin/reset_password' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  id = body['id']
  new_pwd = body['password'].to_s
  unless valid_password?(new_pwd)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  user = users.find { |u| u['__backendId'] == id }
  unless user
    res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  nh = hash_password(new_pwd)
  user['passwordSalt'] = nh['salt']
  user['passwordHash'] = nh['hash']
  write_users(users)
  res.body = { ok: true, user: sanitize_user(user) }.to_json
end

# Username Change Request System
USERNAME_REQUESTS_FILE = File.join(DATA_DIR, 'username_requests.json')

def read_username_requests
  ensure_data
  JSON.parse(File.read(USERNAME_REQUESTS_FILE))
rescue
  []
end

def write_username_requests(requests)
  File.write(USERNAME_REQUESTS_FILE, JSON.pretty_generate(requests))
end

mount_api server, '/api/users/request_username' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  user = uid && users.find { |u| u['__backendId'] == uid }
  
  unless user
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  
  if req.request_method == 'POST'
    body = parse_body(req)
    new_username = body['newUsername'].to_s.strip.downcase
    
    if new_username.empty? || new_username.length < 3
       res.status = 400; res.body = { error: 'invalid_format' }.to_json; next
    end
    
    # Check availability
    if users.any? { |u| u['username'].to_s.downcase == new_username }
       res.status = 409; res.body = { error: 'taken' }.to_json; next
    end
    
    requests = read_username_requests
    
    # Check if pending request exists
    if requests.any? { |r| r['userId'] == user['__backendId'] && r['status'] == 'pending' }
       res.status = 400; res.body = { error: 'pending_request_exists' }.to_json; next
    end
    
    request_id = SecureRandom.hex(8)
    new_req = {
      'id' => request_id,
      'userId' => user['__backendId'],
      'currentUsername' => user['username'],
      'requestedUsername' => new_username,
      'status' => 'pending',
      'createdAt' => Time.now.iso8601
    }
    
    requests << new_req
    write_username_requests(requests)
    
    res.body = { ok: true, message: 'Request submitted' }.to_json
  end
end

mount_api server, '/api/admin/username_requests' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  
  unless admin && (admin['is_admin'] || admin['is_subadmin'])
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  
  requests = read_username_requests
  # Enrich with user details
  requests.each do |r|
    u = users.find { |usr| usr['__backendId'] == r['userId'] }
    if u
      r['userEmail'] = u['email']
      r['userName'] = u['name']
    end
  end
  
  res.body = { requests: requests }.to_json
end

mount_api server, '/api/admin/username_requests/resolve' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  
  unless admin && (admin['is_admin'] || admin['is_subadmin'])
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  
  body = parse_body(req)
  request_id = body['requestId']
  action = body['action'] # 'approve' or 'reject'
  
  requests = read_username_requests
  req_item = requests.find { |r| r['id'] == request_id }
  
  unless req_item
     res.status = 404; res.body = { error: 'not_found' }.to_json; next
  end
  
  if req_item['status'] != 'pending'
     res.status = 400; res.body = { error: 'already_resolved' }.to_json; next
  end
  
  if action == 'approve'
    target_user = users.find { |u| u['__backendId'] == req_item['userId'] }
    if target_user
      # Double check availability
      if users.any? { |u| u['username'].to_s.downcase == req_item['requestedUsername'] && u['__backendId'] != target_user['__backendId'] }
         req_item['status'] = 'failed_taken'
      else
         target_user['username'] = req_item['requestedUsername']
         req_item['status'] = 'approved'
         write_users(users)
      end
    else
      req_item['status'] = 'failed_user_missing'
    end
  elsif action == 'reject'
    req_item['status'] = 'rejected'
  else
    res.status = 400; res.body = { error: 'invalid_action' }.to_json; next
  end
  
  req_item['resolvedAt'] = Time.now.iso8601
  req_item['resolvedBy'] = admin['username']
  
  write_username_requests(requests)
  res.body = { ok: true }.to_json
end

# Admin: register sub-admin
mount_api server, '/api/admin/register_subadmin' do |req, res|
  set_cors(req, res)
  if req.request_method == 'OPTIONS'
    res.status = 204; next
  end
  set_json(res)
  sid = (req.header['cookie'] || []).join.match(/sid=([^;]+)/)
  sid = sid && sid[1]
  uid = sid && SESSIONS[sid]
  users = read_users
  admin = users.find { |u| u['__backendId'] == uid }
  unless admin && admin['is_admin']
    res.status = 401; res.body = { error: 'unauthorized' }.to_json; next
  end
  body = parse_body(req)
  name = body['name']
  email = body['email']
  username = body['username']
  password = body['password']
  phone = body['phone'] || ''
  if [name,email,username,password].any? { |v| v.to_s.strip.empty? }
    res.status = 400; res.body = { error: 'invalid' }.to_json; next
  end
  if users.any? { |u| u['email'].to_s.downcase == email.to_s.downcase || u['username'].to_s.downcase == username.to_s.downcase }
    res.status = 409; res.body = { error: 'exists' }.to_json; next
  end
  unless valid_password?(password)
    res.status = 400; res.body = { error: 'weak_password' }.to_json; next
  end
  profile = { jobTitle: '', company: '', about: '', created: Time.now.iso8601, cards: [] }
  subadmin = create_user_object({ name: name, email: email, username: username, phone: phone, password: password, is_admin: false, data: profile })
  subadmin['is_subadmin'] = true
  users << subadmin
  write_users(users)
  res.body = { ok: true }.to_json
end
trap('INT') { server.shutdown }
server.start
