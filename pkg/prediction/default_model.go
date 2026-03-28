package prediction

// DefaultModel returns a model seeded with well-known port correlation
// patterns derived from common service co-occurrence on Internet hosts.
// Probabilities represent P(target | given), the likelihood that a host
// with "given" port open also has "target" port open.
func DefaultModel() *Model {
	m := NewModel()

	// Web (HTTP/HTTPS)
	m.SetBidirectional(80, 443, 0.85, 0.90)
	m.Set(80, 8080, 0.25)
	m.Set(80, 8443, 0.20)
	m.Set(80, 8000, 0.15)
	m.Set(80, 8888, 0.12)
	m.Set(80, 3000, 0.10)
	m.Set(443, 8443, 0.22)
	m.Set(443, 8080, 0.20)

	// SSH
	m.Set(22, 80, 0.70)
	m.Set(22, 443, 0.65)
	m.Set(22, 21, 0.20)
	m.Set(22, 3306, 0.18)
	m.Set(22, 5432, 0.12)
	m.Set(22, 8080, 0.15)
	m.Set(80, 22, 0.40)
	m.Set(443, 22, 0.45)

	// Mail
	m.SetBidirectional(25, 110, 0.55, 0.60)
	m.SetBidirectional(25, 143, 0.60, 0.65)
	m.Set(25, 465, 0.55)
	m.Set(25, 587, 0.60)
	m.Set(25, 993, 0.50)
	m.Set(25, 995, 0.45)
	m.Set(25, 80, 0.35)
	m.SetBidirectional(143, 993, 0.80, 0.85)
	m.Set(143, 587, 0.55)
	m.SetBidirectional(110, 995, 0.75, 0.80)
	m.Set(110, 587, 0.50)
	m.Set(465, 587, 0.70)
	m.Set(587, 465, 0.65)

	// Windows
	m.SetBidirectional(445, 135, 0.85, 0.85)
	m.SetBidirectional(445, 139, 0.70, 0.75)
	m.Set(445, 3389, 0.50)
	m.Set(445, 5985, 0.30)
	m.Set(445, 5986, 0.20)
	m.Set(135, 3389, 0.45)
	m.Set(135, 5985, 0.25)
	m.Set(3389, 445, 0.70)
	m.Set(3389, 135, 0.65)
	m.Set(3389, 139, 0.50)

	// Database
	m.Set(3306, 22, 0.60)
	m.Set(3306, 80, 0.45)
	m.Set(3306, 443, 0.40)
	m.Set(3306, 33060, 0.25)
	m.Set(5432, 22, 0.55)
	m.Set(5432, 80, 0.40)
	m.Set(5432, 443, 0.35)
	m.Set(27017, 22, 0.45)
	m.Set(27017, 80, 0.35)
	m.Set(27017, 27018, 0.30)
	m.Set(27017, 27019, 0.25)
	m.Set(6379, 22, 0.50)
	m.Set(6379, 80, 0.35)
	m.Set(6379, 443, 0.30)

	// IoT / Routers
	m.Set(23, 80, 0.75)
	m.Set(23, 443, 0.55)
	m.Set(23, 8080, 0.40)
	m.Set(23, 8443, 0.25)
	m.Set(23, 8082, 0.20)

	// Alternate web ports
	m.Set(8080, 80, 0.60)
	m.Set(8080, 443, 0.50)
	m.Set(8080, 22, 0.30)
	m.Set(8080, 8443, 0.25)
	m.Set(8443, 443, 0.55)
	m.Set(8443, 80, 0.50)
	m.Set(8443, 8080, 0.30)
	m.Set(8000, 80, 0.50)
	m.Set(8000, 443, 0.40)
	m.Set(8888, 80, 0.45)
	m.Set(8888, 443, 0.35)

	// FTP
	m.Set(21, 22, 0.55)
	m.Set(21, 80, 0.45)
	m.Set(21, 443, 0.35)

	// DNS
	m.Set(53, 22, 0.40)
	m.Set(53, 80, 0.35)
	m.Set(53, 443, 0.30)

	// Docker / Container
	m.Set(2375, 22, 0.50)
	m.Set(2375, 80, 0.40)
	m.Set(2375, 443, 0.35)
	m.Set(2375, 2376, 0.30)
	m.Set(2376, 22, 0.50)
	m.Set(2376, 80, 0.40)
	m.Set(2376, 2375, 0.30)

	// Monitoring / DevOps
	m.Set(9090, 3000, 0.30)
	m.Set(9090, 80, 0.35)
	m.Set(9090, 443, 0.30)
	m.Set(9090, 22, 0.35)
	m.Set(3000, 80, 0.40)
	m.Set(3000, 443, 0.35)
	m.Set(3000, 9090, 0.25)

	// Alternate SSH
	m.Set(2222, 80, 0.45)
	m.Set(2222, 443, 0.40)
	m.Set(2222, 22, 0.30)

	// Common app stacks
	m.Set(9200, 9300, 0.60) // Elasticsearch
	m.Set(9300, 9200, 0.65)
	m.Set(5601, 9200, 0.50) // Kibana -> ES
	m.Set(9200, 5601, 0.35)

	m.Set(6443, 10250, 0.40) // Kubernetes API -> kubelet
	m.Set(6443, 2379, 0.35)  // Kubernetes API -> etcd
	m.Set(10250, 6443, 0.55)

	m.Set(8161, 61616, 0.55) // ActiveMQ web -> broker
	m.Set(61616, 8161, 0.60)

	m.Set(15672, 5672, 0.70) // RabbitMQ management -> AMQP
	m.Set(5672, 15672, 0.55)

	return m
}
