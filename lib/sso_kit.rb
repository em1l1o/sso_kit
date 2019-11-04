# sso client rails edition
class SsoKit
  # @param [Binding] binding
  def initialize(binding)
    @binding = binding
  end

  # 验证 token
  # @return [OpenStruct] session
  def verify_token
    request = eval('request', @binding)
    cookies = eval('cookies', @binding)
    token = request.headers['token'].presence || cookies['token']
    # TODO: (zhangjiayuan) 考虑对 raise 的异常进行归类整理
    raise '验证 token 失败' if token.blank? || !verify(token)
    @session
  end

  private

  def verify(token)
    # 如果缓存内有 user_session 则无需 touch SSO
    @session = Rails.cache.read(token)
    return true if @session.present?
    # TODO: (zhangjiayuan) use url config file
    url = "#{host}/internal/auth/touch-session?token=#{token}"
    response = HttpHandler.new(url, 'get').run
    result = HttpHandler.parse_response response
    return false if result['status'] != 200
    # 防止中间人攻击，验证返回的 token 是否与传出的一致
    return false if token != result.dig('body', 'token')
    @session = OpenStruct.new(result['body'])
    # 写入缓存
    cache_session(token)
    true
  end

  def host
    Rails.env.development? ? "http://java-sso-xigua-testing.xiguacity.club" : "https://sso.xiguacity.cn"
  end

  def cache_session(token)
    # 计算该 session 距离过期还有多少分钟
    expire_time_in_minute = ((Time.at(@session.expireTime / 1000) - Time.now) / 60).minutes
    # 写入缓存，下次请求会优先访问缓存
    Rails.cache.write(token, @session, expires_in: [expire_time_in_minute, 10.minutes].min)
  end
end

class HttpHandler
  def initialize(url, method, data: {})
    uri = URI(url)
    @request = eval("Net::HTTP::#{method.capitalize}").new(uri)
    @request.set_form_data(data)
  end

  def run
    # send request
    use_ssl = @request.uri.scheme == 'https'
    Net::HTTP.start(@request.uri.host, @request.uri.port, use_ssl: use_ssl, read_timeout: 5) do |http|
      http.request @request
    end
  rescue
    nil
  end

  def self.parse_response(response)
    JSON.parse response.body
  rescue
    {}
  end
end
