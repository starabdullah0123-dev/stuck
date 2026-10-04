// SMS OTP providers for Indian mobile numbers. Choose with SMS_PROVIDER in .env: msg91 | 2factor | fast2sms | twilio
// `to` is always the 10-digit number (server.js normalises +91 / 91 prefixes).
const form = o => new URLSearchParams(o);
async function call(f, url, opt, ok, name) {
  let r, j; try { r = await f(url, opt); j = await r.json().catch(() => ({})); } catch (e) { throw new Error('SMS provider unreachable'); }
  if (!r.ok || !ok(j)) { console.error(`[SMS ${name}]`, r.status, JSON.stringify(j).slice(0, 300)); throw new Error('SMS provider rejected the request'); }
}
const P = {
  // MSG91: needs AUTH key + an OTP template id (DLT-approved template, with ##OTP## variable)
  msg91: (to, code, e, f) => call(f, `https://control.msg91.com/api/v5/otp?${form({ template_id: e.MSG91_TEMPLATE_ID, mobile: '91' + to, authkey: e.MSG91_AUTHKEY, otp: code })}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }, j => j.type === 'success', 'msg91'),
  // 2Factor.in: SMS_TEMPLATE optional (name of the template made in the 2Factor dashboard)
  '2factor': (to, code, e, f) => call(f, `https://2factor.in/API/V1/${encodeURIComponent(e.TWOFACTOR_KEY)}/SMS/${to}/${code}${e.TWOFACTOR_TEMPLATE ? '/' + encodeURIComponent(e.TWOFACTOR_TEMPLATE) : ''}`, {}, j => j.Status === 'Success', '2factor'),
  // Fast2SMS: OTP route
  fast2sms: (to, code, e, f) => call(f, `https://www.fast2sms.com/dev/bulkV2?${form({ authorization: e.FAST2SMS_KEY, route: 'otp', variables_values: code, numbers: to })}`, {}, j => j.return === true, 'fast2sms'),
  twilio: (to, code, e, f) => call(f, `https://api.twilio.com/2010-04-01/Accounts/${e.TWILIO_SID}/Messages.json`, { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(`${e.TWILIO_SID}:${e.TWILIO_TOKEN}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ To: '+91' + to, From: e.TWILIO_FROM, Body: `UNITED KERALAM code: ${code} (valid 10 min)` }) }, j => !!j.sid, 'twilio')
};
const NEED = { msg91: ['MSG91_AUTHKEY', 'MSG91_TEMPLATE_ID'], '2factor': ['TWOFACTOR_KEY'], fast2sms: ['FAST2SMS_KEY'], twilio: ['TWILIO_SID', 'TWILIO_TOKEN', 'TWILIO_FROM'] };
module.exports = async function sendSms(to, code, env = process.env, f = fetch) {
  const name = (env.SMS_PROVIDER || (env.TWILIO_SID ? 'twilio' : '')).toLowerCase();
  if (!P[name] || NEED[name].some(k => !env[k])) throw new Error('SMS is not configured on the server');
  return P[name](to, code, env, f);
};
