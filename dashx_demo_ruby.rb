# rubocop:disable Metrics/MethodLength
# frozen_string_literal: true

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
  config.target_environment = ENV['DASHX_TARGET_ENVIRONMENT']
end

set :default_content_type, :json
conn = PG::Connection.new(ENV['DATABASE_URL'])

get '/register' do
  params => { first_name:, last_name:, email:, password: } rescue nil

  if first_name.nil? ||
     last_name.nil? ||
     email.nil? ||
     password.nil?
    halt 422, 'All fields are required.'
  end

  begin
    result = conn.exec_params(
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
  params => { name:, email:, feedback: } rescue nil

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
                    to: [email, 'sales@dashx.com'],
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

# rubocop:enable Metrics/MethodLength
