# frozen_string_literal: true

require 'sinatra'
require 'pg'
require 'dotenv/load'
require 'bcrypt'
require 'dashx'
require 'json'
require 'jwt'

DashX.configure do |config|
  config.base_uri = ENV['DASHX_BASE_URI']
  config.public_key = ENV['DASHX_PUBLIC_KEY']
  config.private_key = ENV['DASHX_PRIVATE_KEY']
  config.target_environment = ENV['DASHX_TARGET_ENVIRONMENT']
end

set :default_content_type, :json
$conn = PG::Connection.new(ENV['DATABASE_URL'])

helpers do
  def protected!
    bearer = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
    payload = JWT.decode bearer, ENV['JWT_SECRET'], true, { algorithm: 'HS256' }

    result = $conn.exec_params(
      'SELECT * FROM users WHERE id = $1',
      [payload[0]['user']['id']]
    )
    halt 403, { message: 'Invalid token.' }.to_json if result.num_tuples.zero?

    @user = result.first
  rescue JWT::DecodeError
    halt 403, { message: 'Invalid token.' }.to_json
  end
end

post '/register' do
  first_name = params['first_name']
  last_name = params['last_name']
  email = params['email']
  password = params['password']

  if first_name.nil? ||
     last_name.nil? ||
     email.nil? ||
     password.nil?
    halt 422, 'All fields are required.'
  end

  begin
    result = $conn.exec_params(
      'INSERT INTO users (first_name, last_name, email, encrypted_password) VALUES ($1, $2, $3, $4) RETURNING *',
      [first_name, last_name, email, BCrypt::Password.create(password)]
    )
  rescue PG::UniqueViolation
    halt 409, { message: 'User already exists.' }.to_json
  end

  uid = result[0]['id']
  user = {
    firstName: result[0]['first_name'],
    lastName: result[0]['last_name'],
    email: result[0]['email']
  }

  DashX.identify(uid, user)
  DashX.track('User Registered', uid, user)

  { message: 'User created.' }.to_json
end

post '/contact' do
  name = params['name']
  email = params['email']
  feedback = params['feedback']

  if name.nil? ||
     email.nil? ||
     feedback.nil?
    halt 422, 'All fields are required.'
  end

  DashX.deliver('email',
                {
                  content:
                  {
                    name: 'Contact us',
                    from: 'noreply@dashxdemo.com',
                    to: [email, 'sales@dashxdemo.com'],
                    subject: 'Contact Us Form',
                    html_body:
                    `<mjml>
                      <mj-body>
                        <mj-section>
                          <mj-column>
                            <mj-divider border-color="#F45E43"></mj-divider>
                            <mj-text>Thanks for reaching out! We will get back to you soon!</mj-text>
                            <mj-text>Your feedback: </mj-text>
                            <mj-text>Name: ${name}</mj-text>
                            <mj-text>Email: ${email}</mj-text>
                            <mj-text>Feedback: ${feedback}</mj-text>
                            <mj-divider border-color="#F45E43"></mj-divider>
                          </mj-column>
                        </mj-section>
                      </mj-body>
                    </mjml>`
                  }
                })

  {
    message: 'Thanks for reaching out! We will get back to you soon.'
  }.to_json
end

post '/login' do
  email = params['email']
  password = params['password']

  halt 401, 'Incorrect email or password.' if email.nil? || password.nil?

  result = $conn.exec_params(
    'SELECT id, first_name, last_name, email, encrypted_password FROM users WHERE email = $1',
    [email]
  )

  halt 401, { message: 'Incorrect email or password.' }.to_json if result.num_tuples.zero?

  if BCrypt::Password.new(result[0]['encrypted_password']) != password
    halt 401, { message: 'Incorrect email or password.' }.to_json
  end

  user = result.first.except('encrypted_password')
  payload = { user: user, dashx_token: DashX.generate_identity_token(user['id']) }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'

  { message: 'User logged in.', token: token }.to_json
end

get '/profile' do
  protected!

  begin
    result = $conn.exec_params(
      'SELECT id, first_name, last_name, email, avatar FROM users
      WHERE id = $1',
      [@user['id']]
    )
  rescue StandardError => e
    halt 500, { message: e.to_s }.to_json
  end

  { message: 'Successfully fetched.', user: result.first }.to_json
end

patch '/update-profile' do
  protected!

  first_name = params['first_name']
  last_name = params['last_name']
  email = params['email']
  avatar = params['avatar']

  if !email.nil? && @user['email'] != email
    result = $conn.exec_params('SELECT * FROM users WHERE email = $1', [email])

    halt 409, { message: 'Email already exists.' }.to_json unless result.num_tuples.zero?
  end

  begin
    result = $conn.exec_params(
      'UPDATE users SET first_name = $1, last_name = $2, email = $3, avatar = $4
      WHERE id = $5 RETURNING id, first_name, last_name, email, avatar',
      [
        first_name || @user['first_name'],
        last_name || @user['last_name'],
        email || @user['email'],
        avatar || @user['avatar'],
        @user['id']
      ]
    )
  rescue StandardError => e
    halt 500, { message: e.to_s }.to_json
  end

  user = result.first
  DashX.identify(
    user['id'],
    {
      firstName: user['first_name'],
      lastName: user['last_name'],
      email: user['email']
    }
  )

  { message: 'Profile updated.', user: user }.to_json
end

post '/forgot-password' do
  email = params['email']

  halt 400, { message: 'Email is required.' }.to_json if email.nil?

  result = $conn.exec_params(
    'SELECT * FROM users WHERE email = $1',
    [email]
  )

  halt 404, { message: 'This email does not exist in our records.' }.to_json if result.num_tuples.zero?
  exp = Time.now.to_i + (15 * 60)
  payload = { email: email, exp: exp }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'

  DashX.deliver(
    'email/forgot-password',
    {
      to: email,
      data: { token: token }
    }
  )

  { message: 'Check your inbox for a link to reset your password.' }.to_json
end

post '/reset-password' do
  token = params['token']
  password = params['password']

  halt 400, { message: 'Token is required.' }.to_json if token.nil?
  halt 400, { message: 'Password is required.' }.to_json if password.nil?

  begin
    payload = JWT.decode token, ENV['JWT_SECRET'], true, { algorithm: 'HS256' }
  rescue JWT::ExpiredSignature
    halt 422, { message: 'Your reset password link has expired.' }.to_json
  end

  email = payload[0]['email']

  result = $conn.exec_params(
    'UPDATE users SET encrypted_password = $1 WHERE email = $2 RETURNING id',
    [BCrypt::Password.create(password), email]
  )

  halt 422, { message: 'Invalid reset password link.' }.to_json if result.num_tuples.zero?

  { message: 'You have successfully reset your password.' }.to_json
end

get '/posts' do
  protected!

  limit = params['limit'] || 30
  offset = params['offset'] || 0

  result = $conn.exec_params(
    'SELECT posts.*, first_name, last_name, email, bookmarked_at FROM posts
      INNER JOIN users ON posts.user_id = users.id
      LEFT JOIN bookmarks ON bookmarks.post_id = posts.id and bookmarks.user_id = $1
      ORDER BY posts.created_at DESC LIMIT $2 OFFSET $3',
    [@user['id'], limit, offset]
  )

  posts_list = []
  result.each do |row|
    row['user'] = {
      id: row['user_id'],
      first_name: row['first_name'],
      last_name: row['last_name'],
      email: row['email']
    }
    posts_list.push(row.except('first_name', 'last_name', 'email'))
  end

  { posts: posts_list }.to_json
end

post '/posts' do
  protected!

  text = params['text'] || ''
  image = params['image']
  video = params['video']

  result = $conn.exec_params(
    'INSERT INTO posts (user_id, text, image, video) VALUES ($1, $2, $3, $4) RETURNING *',
    [@user['id'], text, image, video]
  )

  post = result.first
  DashX.track('Post Created', @user['id'], post)
  { message: 'Successfully created post.', post: post }.to_json
end

put '/posts/:post_id/toggle-bookmark' do
  protected!

  result = $conn.exec_params(
    'INSERT INTO bookmarks (user_id, post_id) VALUES ($1, $2) ON CONFLICT (user_id, post_id)
    DO UPDATE SET bookmarked_at = (CASE WHEN bookmarks.bookmarked_at IS NULL THEN NOW() ELSE NULL END)
    RETURNING *;',
    [@user['id'], params['post_id']]
  )

  bookmark = result.first
  if bookmark['bookmarked_at'].nil?
    DashX.track('Post Unbookmarked', @user['id'], bookmark)
  else
    DashX.track('Post Bookmarked', @user['id'], bookmark)
  end

  status 204
end

get '/posts/bookmarked' do
  protected!

  limit = params['limit'] || 30
  offset = params['offset'] || 0

  result = $conn.exec_params(
    'SELECT posts.*, first_name, last_name, email, bookmarked_at FROM posts
    INNER JOIN users ON posts.user_id = users.id
    INNER JOIN bookmarks ON posts.id = bookmarks.post_id
    where bookmarks.user_id = $1 AND bookmarks.bookmarked_at IS NOT NULL
    ORDER BY posts.created_at DESC LIMIT $2 OFFSET $3',
    [@user['id'], limit, offset]
  )

  posts_list = []
  result.each do |row|
    row['user'] = {
      id: row['user_id'],
      first_name: row['first_name'],
      last_name: row['last_name'],
      email: row['email']
    }
    posts_list.push(row.except('first_name', 'last_name', 'email'))
  end

  { posts: posts_list }.to_json
end

get '/products' do
  protected!

  begin
    product_names = %w[pen coffee-mug notebook notebook-subscription paper-subscription]

    products = []
    product_names.each { |name| products.push(DashX.fetch_item(name).parsed_response['data']['fetchItem']) }
  rescue StandardError => e
    halt 500, { message: e.to_s }.to_json
  end

  { message: 'Successfully fetched.', products: products }.to_json
end

get '/products/:slug' do
  protected!

  begin
    product = DashX.fetch_item(params['slug']).parsed_response['data']['fetchItem']
  rescue StandardError => e
    halt 500, { message: e.to_s }.to_json
  end

  { message: 'Successfully fetched.', product: product }.to_json
end
