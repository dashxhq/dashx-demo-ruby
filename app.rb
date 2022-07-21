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

    @user = result[0]
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
                    to: [email, 'ravi@keepworks.com'],
                    subject: 'Contact Us Form',
                    html_body: html_body
                  }
                })

  {
    message: 'Thanks for reaching out! We will get back to you soon.'
  }.to_json
end

def html_body
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
end

post '/login' do
  email = params['email']
  password = params['password']

  halt 422, 'email and password are required.' if email.nil? || password.nil?

  result = $conn.exec_params(
    'SELECT id, first_name, last_name, email, encrypted_password FROM users WHERE email = $1',
    [email]
  )

  halt 401, { message: 'Incorrect email or password.' }.to_json if result.num_tuples.zero?

  if BCrypt::Password.new(result[0]['encrypted_password']) != password
    halt 401, { message: 'Incorrect email or password.' }.to_json
  end

  user = result[0].except('encrypted_password')
  payload = { user: user, dashx_token: DashX.generate_identity_token(user['id']) }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'

  { message: 'User logged in.', token: token }.to_json
end

patch '/update-profile' do
  first_name = params['first_name']
  last_name = params['last_name']
  email = params['email']
  avatar = params['avatar']

  protected!
  email.nil?.to_s
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

  user = result[0]
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
