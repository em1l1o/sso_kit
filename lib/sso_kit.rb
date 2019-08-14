# sso client rails edition
class SsoKit
  def initialize(binding)
    @binding = binding
  end

  # 验证 token
  def verify_token
    cookies = eval('cookies', @binding)
    token = cookies['token']
    # TODO (zhangjiayuan): 考虑对 raise 的异常进行归类整理
    raise '验证 token 失败' if token.blank? || !verify(token)
    true
  end

  # 请求 token
  def self.request_token(some_id)
    token(some_id)
  end

  private

  def verify(token)
    # TODO (zhangjiayuan): use uri config file
    url = "https://xiguacity.cn/server/auth/touch-session"
    data = { token: token }
    response = HttpHandler.new(url, 'post', data).run
    return false if response.code != 200
    result = JSON.parse response.body
    # 防止中间人攻击，验证返回的 token 是否与传出的一致
    return false if token != result['token']
    true
  end

  def token(some_id)
    # TODO (zhangjiayuan): use uri config file
    url = "https://xiguacity.cn/server/auth/create-session"
    data = { some_id: some_id }
    response = HttpHandler.new(url, 'post', data).run
    return nil if response.code != 200
    result = JSON.parse response.body
    result['token']
  end
end

class HttpHandler
  def initialize(url, method, data)
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
  end
end
