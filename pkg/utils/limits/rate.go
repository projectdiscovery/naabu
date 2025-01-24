package limits

func RateLimitWithProxy(rateLimit int) int {
	return rateLimit / 2
}
