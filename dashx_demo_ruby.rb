require 'sinatra'
require 'pg'
require 'dotenv/load'
require 'bcrypt'
require 'dashx'
require 'json'

DashX.configure do |config|
  config.base_uri = ENV['DASHX_BASE_URI']
  config.public_key = ENV['DASHX_PUBLIC_KEY']
  config.private_key = ENV['DASHX_PRIVATE_KEY']
  config.target_environment = ENV['DASHX_TARGET_ENV']
end

set :default_content_type, :json
conn = PG::Connection.new(ENV['DATABASE_URI'])

get '/register' do
  params => { first_name:, last_name:, email:, password:} rescue nil

  if first_name.nil? ||
     last_name.nil? ||
     email.nil? ||
     password.nil?
    halt 422, 'All fields are required.'
  end

  existing_user = conn.exec_params('SELECT * from users where email = $1', [email])

  if existing_user.num_tuples.zero?
    result = conn.exec_params(
      'INSERT INTO users (first_name, last_name, email, encrypted_password) VALUES ($1, $2, $3, $4) RETURNING *',
      [first_name, last_name, email, BCrypt::Password.create(password)]
    )

    uid = result[0]['id']
    user = {
      firstName: result[0]['first_name'],
      lastName: result[0]['last_name'],
      email: result[0]['email']
    }

    DashX.identify(uid, user)
    DashX.track('User Registered', uid, user)

    { message: 'User created.' }.to_json
  else
    halt 409, 'User already exists.'
  end
end
