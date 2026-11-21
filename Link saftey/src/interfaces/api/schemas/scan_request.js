const { AppError } = require('../../../shared/app_error');
function validateCreateScanBody(body, maxUrlLength) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw AppError.invalid('Request body must be a JSON object.');
  if (Object.keys(body).some(key => key !== 'url')) throw AppError.invalid('Only the url field is accepted.');
  if (typeof body.url !== 'string') throw AppError.invalid('The url field must be a string.');
  const url = body.url.trim();
  if (!url) throw AppError.invalid('Enter a URL to analyze.');
  if (url.length > maxUrlLength) throw AppError.invalid(`URL must be ${maxUrlLength} characters or fewer.`);
  return url;
}
module.exports = { validateCreateScanBody };


