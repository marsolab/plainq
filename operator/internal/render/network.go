package render

import (
	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Service renders the client-facing Service.
func Service(pq *plainqv1alpha1.PlainQ) *corev1.Service {
	names := NamesFor(pq)

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        names.Service(),
			Namespace:   pq.Namespace,
			Labels:      MergeLabels(Labels(pq), pq.Spec.Networking.Service.Labels),
			Annotations: pq.Spec.Networking.Service.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType(pq),
			Selector: SelectorLabels(pq),
			Ports:    servicePorts(pq),
		},
	}
}

// HeadlessService gives cluster pods stable per-pod DNS. It publishes
// not-ready addresses because a forming cluster has no ready pods yet: every
// node is waiting to see its peers, and readiness cannot arrive first.
func HeadlessService(pq *plainqv1alpha1.PlainQ) *corev1.Service {
	names := NamesFor(pq)

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.Headless(),
			Namespace: pq.Namespace,
			Labels:    Labels(pq),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:                corev1.ClusterIPNone,
			PublishNotReadyAddresses: true,
			Selector:                 SelectorLabels(pq),
			Ports:                    servicePorts(pq),
		},
	}
}

// AliasService renders the stable name clients connect to.
//
// It exists because a cutover cannot be performed by editing an instance's own
// Service: those are owned by their PlainQ and reconciled with server-side
// apply, so the next pass would revert the edit and silently take traffic
// back. The alias is a separate Service whose selector the operator points at
// whichever instance currently claims the name, which makes a cutover a single
// atomic, reversible edit.
func AliasService(pq *plainqv1alpha1.PlainQ) *corev1.Service {
	name := pq.Spec.Networking.Alias.Name
	if name == "" {
		return nil
	}

	labels := MergeLabels(Labels(pq), map[string]string{LabelAlias: name})

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: pq.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType(pq),
			Selector: SelectorLabels(pq),
			Ports:    servicePorts(pq),
		},
	}
}

func serviceType(pq *plainqv1alpha1.PlainQ) corev1.ServiceType {
	if t := pq.Spec.Networking.Service.Type; t != "" {
		return t
	}

	return corev1.ServiceTypeClusterIP
}

func servicePorts(pq *plainqv1alpha1.PlainQ) []corev1.ServicePort {
	ports := []corev1.ServicePort{
		{
			Name:       grpcPortName,
			Port:       pq.Spec.Listeners.GRPC.Port,
			TargetPort: intstr.FromString(grpcPortName),
			Protocol:   corev1.ProtocolTCP,
		},
		{
			Name:       httpPortName,
			Port:       pq.Spec.Listeners.HTTP.Port,
			TargetPort: intstr.FromString(httpPortName),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	if pq.Spec.Cluster.Enabled {
		ports = append(ports,
			corev1.ServicePort{
				Name:       clusterPortName,
				Port:       pq.Spec.Cluster.ClusterPort,
				TargetPort: intstr.FromString(clusterPortName),
				Protocol:   corev1.ProtocolTCP,
			},
			corev1.ServicePort{
				Name:       gossipTCPPortName,
				Port:       pq.Spec.Cluster.GossipPort,
				TargetPort: intstr.FromString(gossipTCPPortName),
				Protocol:   corev1.ProtocolTCP,
			},
			corev1.ServicePort{
				Name:       gossipUDPPortName,
				Port:       pq.Spec.Cluster.GossipPort,
				TargetPort: intstr.FromString(gossipUDPPortName),
				Protocol:   corev1.ProtocolUDP,
			},
		)
	}

	return ports
}

// Ingress renders external exposure.
func Ingress(pq *plainqv1alpha1.PlainQ) *networkingv1.Ingress {
	spec := pq.Spec.Networking.Ingress
	if !spec.Enabled {
		return nil
	}

	names := NamesFor(pq)

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        names.Ingress(),
			Namespace:   pq.Namespace,
			Labels:      Labels(pq),
			Annotations: spec.Annotations,
		},
	}

	if class := spec.ClassName; class != "" {
		ingress.Spec.IngressClassName = &class
	}

	for _, host := range spec.Hosts {
		rule := networkingv1.IngressRule{Host: host.Host}
		rule.HTTP = &networkingv1.HTTPIngressRuleValue{}

		for _, p := range host.Paths {
			pathType := networkingv1.PathTypePrefix
			if p.PathType != "" {
				pathType = networkingv1.PathType(p.PathType)
			}

			portName := httpPortName
			if p.Port == grpcPortName {
				portName = grpcPortName
			}

			rule.HTTP.Paths = append(rule.HTTP.Paths, networkingv1.HTTPIngressPath{
				Path:     pathOr(p.Path),
				PathType: &pathType,
				Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{
						Name: names.Service(),
						Port: networkingv1.ServiceBackendPort{Name: portName},
					},
				},
			})
		}

		ingress.Spec.Rules = append(ingress.Spec.Rules, rule)
	}

	for _, tls := range spec.TLS {
		ingress.Spec.TLS = append(ingress.Spec.TLS, networkingv1.IngressTLS{
			Hosts:      tls.Hosts,
			SecretName: tls.SecretName,
		})
	}

	return ingress
}

func pathOr(p string) string {
	if p == "" {
		return "/"
	}

	return p
}

// NetworkPolicy renders a default-deny ingress policy with explicit
// allowances.
//
// This matters more than usual here. The gRPC listener carries no
// authentication of its own, so network position is what protects the queue
// API; the HTTP listener is JWT-gated but also serves the admin UI. Both
// belong on a short list of callers.
//
// Cluster ports are opened to the instance's own pods so consensus and gossip
// keep working under the policy.
func NetworkPolicy(pq *plainqv1alpha1.PlainQ) *networkingv1.NetworkPolicy {
	spec := pq.Spec.Networking.NetworkPolicy
	if !spec.Enabled {
		return nil
	}

	names := NamesFor(pq)

	grpcPort := intstr.FromInt32(pq.Spec.Listeners.GRPC.Port)
	httpPort := intstr.FromInt32(pq.Spec.Listeners.HTTP.Port)
	tcp := corev1.ProtocolTCP

	rules := []networkingv1.NetworkPolicyIngressRule{}

	if len(spec.AllowFrom) > 0 {
		rules = append(rules, networkingv1.NetworkPolicyIngressRule{
			From: peers(spec.AllowFrom),
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &grpcPort},
				{Protocol: &tcp, Port: &httpPort},
			},
		})
	}

	if pq.Spec.Cluster.Enabled {
		clusterPort := intstr.FromInt32(pq.Spec.Cluster.ClusterPort)
		gossipPort := intstr.FromInt32(pq.Spec.Cluster.GossipPort)
		udp := corev1.ProtocolUDP

		rules = append(rules, networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{
				{PodSelector: &metav1.LabelSelector{MatchLabels: SelectorLabels(pq)}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &clusterPort},
				{Protocol: &tcp, Port: &gossipPort},
				{Protocol: &udp, Port: &gossipPort},
			},
		})
	}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.NetworkPolicy(),
			Namespace: pq.Namespace,
			Labels:    Labels(pq),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: SelectorLabels(pq)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     rules,
		},
	}
}

func peers(allow []plainqv1alpha1.NetworkPolicyPeer) []networkingv1.NetworkPolicyPeer {
	out := make([]networkingv1.NetworkPolicyPeer, 0, len(allow))

	for _, p := range allow {
		out = append(out, networkingv1.NetworkPolicyPeer{
			PodSelector:       p.PodSelector,
			NamespaceSelector: p.NamespaceSelector,
		})
	}

	return out
}
