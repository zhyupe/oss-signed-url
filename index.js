const enc = new TextEncoder('utf-8')

const hmacSHA1 = async (key, content) => {
  if (!window.crypto || !window.crypto.subtle) {
    const module = await import('./hmac-sha1.js')
    return module.default(key, content)
  }

  const cryptoKey = await crypto.subtle.importKey('raw', enc.encode(key), {
    name: 'HMAC',
    hash: { name: 'SHA-1' }
  }, false, ['sign'])

  const sign = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(content))
  return btoa(String.fromCharCode(...new Uint8Array(sign)))
}

const sign = (aks, method, path, expires, md5 = '', ctype = '') => {
  const content = `${method}\n${md5}\n${ctype}\n${expires}\n${path}`
  return hmacSHA1(aks, content)
}

const $id = (id) => document.getElementById(id)
const render = async () => {
  const akid = $id('akid').value
  const aks = $id('aks').value
  const url = $id('url').value
  const method = $id('method_get').checked ? 'GET' : 'PUT'
  const md5 = method === 'GET' ? '' : $id('md5').value
  const ctype = method === 'GET' ? '' : $id('ctype').value
  const expires = Math.floor(new Date($id('expires').value).getTime() / 1000)

  $id('md5').disabled = method === 'GET'
  $id('ctype').disabled = method === 'GET'

  const output = $id('output')
  if (akid && aks && url && expires) {
    try {
      const signedUrl = new URL(url)
      const params = signedUrl.searchParams
      const bucket = signedUrl.hostname.split('.')[0]
      const path = signedUrl.pathname

      params.set('OSSAccessKeyId', akid)
      params.set('Expires', expires)
      params.set('Signature', await sign(aks, method, `/${bucket}${path}`, expires, md5, ctype))

      output.href = signedUrl.toString()
      output.textContent = output.href
      return
    } catch (e) {
      console.error(e)
    }
  }

  output.href = 'javascript:void(0)'
  output.textContent = '信息不完整'
}

$id('app').addEventListener('input', render)
$id('app').addEventListener('change', render)
render()
