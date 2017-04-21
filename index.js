const crypto = require('crypto')
const SALT_BYTES = 16
const HASH_BYTES = 32
const HASH_ALGORITM = "sha512"

const SALT_BASE64_LENGTH = Math.ceil(SALT_BYTES/3)*4
const HASH_BASE64_LENGTH = Math.ceil(HASH_BYTES/3)*4

const BASE64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"

exports.hashSync = function(password, iteration = 15) {
	if (iteration < 0 || 63 < iteration) {
		throw new Error("iteration must be between 0 and 63")
	}

	const salt = crypto.randomBytes(SALT_BYTES).toString("base64")
	const hash = crypto.pbkdf2Sync(password, salt, 1 << iteration, HASH_BYTES, HASH_ALGORITM).toString("base64")

	return BASE64[iteration] + salt + hash
}

exports.hash = function(password, iteration = 15) {
	return new Promise(function(resolve, reject) {
		if (iteration < 0 || 63 < iteration) {
			reject(new Error("iteration must be between 0 and 63"))
		}

		const salt = crypto.randomBytes(SALT_BYTES).toString("base64")
		crypto.pbkdf2(password, salt, 1 << iteration, HASH_BYTES, HASH_ALGORITM, (err, key) => {
			if (err) {
				reject(err)
			} else {
				resolve(BASE64[iteration] + salt + key.toString("base64"))
			}
		})
	})
}

exports.validateSync = function(password, hashed) {
	const iteration = BASE64.indexOf(hashed[0])
	const salt = hashed.substr(1, SALT_BASE64_LENGTH)
	const hash = hashed.substr(SALT_BASE64_LENGTH + 1)

	return crypto.pbkdf2Sync(password, salt, 1 << iteration, HASH_BYTES, HASH_ALGORITM).toString("base64") == hash
}

exports.validate = function(password, hashed) {
	return new Promise(function(resolve, reject) {
		const iteration = BASE64.indexOf(hashed[0])
		const salt = hashed.substr(1, SALT_BASE64_LENGTH)
		const hash = hashed.substr(SALT_BASE64_LENGTH + 1)

		crypto.pbkdf2(password, salt, 1 << iteration, HASH_BYTES, HASH_ALGORITM, (err, key) => {
			if (err) {
				reject(err)
			} else {
				resolve(hash == key.toString("base64"))
			}
		})
	})
}

