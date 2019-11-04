# sso client rails edition
class SsoKit
  # @param [Binding] binding
  def initialize(binding)
    @request = eval('request', binding)
    @cookies = eval('cookies', binding)
  end

  # 验证 token
  # @return [OpenStruct] session
  def verify_token
    token = @request.headers['token'].presence || compatible_token
    # TODO: (zhangjiayuan) 考虑对 raise 的异常进行归类整理
    raise '验证 token 失败' if token.blank? || !verify(token)
    @session
  end

  private

  def verify(token)
    # TODO: (zhangjiayuan) use url config file
    url = "#{host}/internal/auth/touch-session?token=#{token}"
    response = HttpHandler.new(url, 'get').run
    result = HttpHandler.parse_response response
    return false if result['status'] != 200
    # 防止中间人攻击，验证返回的 token 是否与传出的一致
    return false if token != result.dig('body', 'token')
    @session = OpenStruct.new(result['body'])
    true
  end

  # 针对无法将 token 放入 header 的请求所做的兼容，例如 rails 生成的页面 (erb, slim 页面等)
  def compatible_token
    # 兼容教学后台老页面，以及微信运营平台老页面
    if @request.path.match?(/\/admin/) || @request.user_agent.match?(/MicroMessenger/i)
      @cookies['token']
    else
      @cookies['study_token']
    end
  end

  def host
    Rails.env.development? ? "http://java-sso-xigua-testing.xiguacity.club" : "https://sso.xiguacity.cn"
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
