// Objects are cached under the checksum S3 reports (ETag / Content-MD5).
function cacheKey(object) {
  return `obj:${object.md5}`;
}
const headers = (object) => ({ "Content-MD5": object.contentMd5 });
const hashAlgorithm = "sha256";
