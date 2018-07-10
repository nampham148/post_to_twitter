require 'base64'
require 'cgi'
require 'openssl'
require 'net/http'
require 'securerandom'

class StaticPagesController < ApplicationController
  include TwitterReq

  before_action :not_have_code, only: [:new, :create, :logout]
  before_action :have_code, only: [:home, :login, :signin]
  
  def home
  end

  def login
    resp = twitter_login
    puts resp.body
    puts resp.code
    if resp.code == "200"
      result = parse_oauth(resp.body)
      redirect_to "https://api.twitter.com/oauth/authenticate?oauth_token=#{result["oauth_token"]}"
    else
      redirect_to root_url
    end
  end

  def signin
    resp = get_access_code(params[:oauth_token], params[:oauth_verifier])
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
    post_tweet(params[:tweet][:content])
    redirect_to "/new_post"
  end

  def logout
    reset_session
    redirect_to root_url
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

    def not_have_code
      redirect_to root_url if session[:oauth_token].nil?
    end

    def have_code
      redirect_to '/new_post' unless session[:oauth_token].nil?
    end
end
