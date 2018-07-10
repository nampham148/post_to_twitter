module TwitterReq
  OAUTH_SIGNATURE_METHOD = 'HMAC-SHA1'
  OAUTH_VERSION = '1.0'
  OAUTH_CALLBACK = 'http://localhost:3000/sign-in-with-twitter/'

  def twitter_login
    authorize_map = default_authorize_map
    authorize_map = add_value_map authorize_map, :oauth_callback, OAUTH_CALLBACK
    authorize_map = add_value_map authorize_map, :oauth_signature, 
                      oauth_signature('https://api.twitter.com/oauth/request_token', parameter_string(authorize_map))
    resp = post_http('/oauth/request_token', authorization(authorize_map))
  end

  def get_access_code(oauth_token, oauth_verifier)
    authorize_map = default_authorize_map
    authorize_map = add_value_map authorize_map, :oauth_token, oauth_token   
    authorize_map = add_value_map authorize_map, :oauth_signature,
                      oauth_signature('https://api.twitter.com/oauth/access_token', parameter_string(authorize_map))

    resp = post_http('/oauth/access_token', authorization(authorize_map), "oauth_verifier=#{oauth_verifier}")
  end

  def post_tweet(tweet)
    authorize_map = default_authorize_map
    authorize_map = add_value_map authorize_map, :oauth_token, session[:oauth_token]
    authorize_map = add_value_map authorize_map, :oauth_signature,
                      oauth_signature('https://api.twitter.com/1.1/statuses/update.json', 
                                       parameter_string(authorize_map, tweet),
                                       session[:oauth_token_secret])

    data = "status=#{CGI.escape(tweet).gsub("+", "%20")}"
    post_http('/1.1/statuses/update.json?include_entities=true', authorization(authorize_map), data)
  end

  def post_http(path, authorization, data='')
    uri = URI.parse("https://api.twitter.com")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    headers = {
      'Authorization' => authorization
    }

    resp, data = http.post(path, data, headers)
    return resp
  end

  def oauth_signature(base_url, parameter_string, oauth_token_secret='')
    signature_base_string = "POST&#{CGI.escape(base_url)}&#{CGI.escape(parameter_string)}"
    signing_key = "#{CGI.escape(ENV["oauth_consumer_secret"])}&#{CGI.escape(oauth_token_secret)}"
    Base64.strict_encode64("#{OpenSSL::HMAC.digest('sha1', signing_key, signature_base_string)}")
  end

  def authorization(authorize_map)
    authorization = %Q|OAuth |
    authorize_list = []
    authorize_map.each do |key, value|
      authorize_list.push(%Q|#{CGI.escape(key.to_s)}="#{CGI.escape(value)}"|)
    end
    authorization += authorize_list.join(", ")
    return authorization
  end

  def parameter_string(authorize_map, tweet=nil)
    authorize_list = tweet.nil? ? [] : ['include_entities=true']
    status_string = tweet.nil? ? '' : "&status=#{CGI.escape(tweet).gsub("+", "%20")}"
    authorize_map.each do |key, value|
      authorize_list.push("#{CGI.escape(key.to_s)}=#{CGI.escape(value)}")
    end
    authorize_list.join('&') + status_string
  end

  def default_authorize_map
    { oauth_consumer_key: ENV['oauth_consumer_key'],
      oauth_nonce: SecureRandom.hex,
      oauth_signature_method: OAUTH_SIGNATURE_METHOD,
      oauth_timestamp: "#{Time.now.to_i}",
      oauth_version: OAUTH_VERSION }
  end

  def add_value_map authorize_map, key, value
    authorize_map[key] = value
    Hash[ authorize_map.sort_by{ |key, value| key } ]
  end
end