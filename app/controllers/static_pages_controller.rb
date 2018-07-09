require 'base64'
require 'cgi'
require 'openssl'
require 'net/http'
require 'securerandom'

class StaticPagesController < ApplicationController
  before_action :has_code, only: [:new]

  def home
  end

  def login
    uri = URI.parse("https://api.twitter.com")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    path = '/oauth/request_token'
    http_method = 'POST'
    base_url = 'https://api.twitter.com/oauth/request_token'

    authorize_map = { oauth_callback: 'http://localhost:3000/sign-in-with-twitter/', 
                      oauth_consumer_key: 'hZQt1QkRbu3KsBp6DzQ7ogXzh',
                      oauth_nonce: SecureRandom.hex,
                      oauth_signature_method: 'HMAC-SHA1',
                      oauth_timestamp: "#{Time.now.to_i}",
                      oauth_version: '1.0' }

    authorize_list = []
    authorize_map.each do |key, value|
      authorize_list.push("#{CGI.escape(key.to_s)}=#{CGI.escape(value)}")
    end

    signature_base_string = "#{http_method}&#{CGI.escape(base_url)}&#{CGI.escape(authorize_list.join('&'))}"
    signing_key = "#{CGI.escape('ozv2GYbC45XozBnHJyXb1kkLHsenqg7XRwEznmbYSA4vDZfLlg')}&"
    authorize_map[:oauth_signature] = Base64.encode64("#{OpenSSL::HMAC.digest('sha1', signing_key, signature_base_string)}")

    authorize_map = Hash[ authorize_map.sort_by{ |key, value| key } ]

    authorization = %Q|OAuth |

    authorize_list = []
    authorize_map.each do |key, value|
      authorize_list.push(%Q|#{CGI.escape(key.to_s)}="#{CGI.escape(value)}"|)
    end
    authorization += authorize_list.join(", ")

    headers = {
      'Authorization' => authorization
    }

    resp, data = http.post(path, data, headers)

    if resp.code == "200"
      result = parse_oauth(resp.body)
      puts result["oauth_token"]
      redirect_to "https://api.twitter.com/oauth/authenticate?oauth_token=#{result["oauth_token"]}"
    else
      redirect_to root_url
    end
  end

  def signin
    puts params[:oauth_token]
    puts params[:oauth_verifier]

    uri = URI.parse("https://api.twitter.com")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    path = '/oauth/access_token'
    http_method = 'POST'
    base_url = 'https://api.twitter.com/oauth/access_token'

    authorize_map = { oauth_consumer_key: 'hZQt1QkRbu3KsBp6DzQ7ogXzh',
                      oauth_nonce: SecureRandom.hex,
                      oauth_signature_method: 'HMAC-SHA1',
                      oauth_timestamp: "#{Time.now.to_i}",
                      oauth_token: params[:oauth_token],
                      oauth_version: '1.0' }

    authorize_list = []
    authorize_map.each do |key, value|
      authorize_list.push("#{CGI.escape(key.to_s)}=#{CGI.escape(value)}")
    end

    signature_base_string = "#{http_method}&#{CGI.escape(base_url)}&#{CGI.escape(authorize_list.join('&'))}"
    signing_key = "#{CGI.escape('ozv2GYbC45XozBnHJyXb1kkLHsenqg7XRwEznmbYSA4vDZfLlg')}&"
    authorize_map[:oauth_signature] = Base64.encode64("#{OpenSSL::HMAC.digest('sha1', signing_key, signature_base_string)}")

    authorize_map = Hash[ authorize_map.sort_by{ |key, value| key } ]
    authorization = %Q|OAuth |

    authorize_list = []
    authorize_map.each do |key, value|
      authorize_list.push(%Q|#{CGI.escape(key.to_s)}="#{CGI.escape(value)}"|)
    end
    authorization += authorize_list.join(", ")

    data = "oauth_verifier=#{params[:oauth_verifier]}"
    headers = {
      'Authorization' => authorization
    }

    resp, data = http.post(path, data, headers)
    if resp.code == "200"
      result = parse_oauth(resp.body)
      session[:oauth_token] =  result["oauth_token"]
      session[:oauth_token_secret] = result["oauth_token_secret"]
      redirect_to '/new_post'
    else
      redirect_to root_url
    end
  end

  def new
  end

  def create
    puts params

    uri = URI.parse("https://api.twitter.com")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    path = '/1.1/statuses/update.json?include_entities=true'
    http_method = 'POST'
    base_url = 'https://api.twitter.com/1.1/statuses/update.json'
    
    authorize_map = { oauth_consumer_key: 'hZQt1QkRbu3KsBp6DzQ7ogXzh',
                      oauth_nonce: 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg',
                      oauth_signature_method: 'HMAC-SHA1',
                      oauth_timestamp: "#{Time.now.to_i}",
                      oauth_token: session[:oauth_token],
                      oauth_version: '1.0' }

    authorize_list = ['include_entities=true']
    authorize_map.each do |key, value|
      authorize_list.push("#{CGI.escape(key.to_s)}=#{CGI.escape(value)}")
    end

    parameter_string = authorize_list.join('&') + "&status=#{CGI.escape(params[:tweet][:content]).gsub("+", "%20")}"

    signature_base_string = "#{http_method}&#{CGI.escape(base_url)}&#{CGI.escape(parameter_string)}"
    puts signature_base_string

    signing_key = "#{CGI.escape('ozv2GYbC45XozBnHJyXb1kkLHsenqg7XRwEznmbYSA4vDZfLlg')}&#{CGI.escape(session[:oauth_token_secret])}"
    authorize_map[:oauth_signature] = Base64.strict_encode64("#{OpenSSL::HMAC.digest('sha1', signing_key, signature_base_string)}")

    authorize_map = Hash[ authorize_map.sort_by{ |key, value| key } ]
    authorization = %Q|OAuth |

    authorize_list = []
    authorize_map.each do |key, value|
      authorize_list.push(%Q|#{CGI.escape(key.to_s)}="#{CGI.escape(value)}"|)
    end
    authorization += authorize_list.join(", ")

    data = "status=#{CGI.escape(params[:tweet][:content]).gsub("+", "%20")}"
    headers = {
      'Authorization' => authorization
    }

    resp, data = http.post(path, data, headers)
    redirect_to "/new_post"

  end

  private
    def parse_oauth(str)
      Hash[
        str.split('&').map do |pair|
          k, v = pair.split('=', 2)
          [k, v]
        end
      ]
    end

    def has_code
      redirect_to root_url unless !session[:oauth_token].nil?
    end
end
