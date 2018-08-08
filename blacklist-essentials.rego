package kubernetes.admission

import data.kubernetes.namespaces

deny[msg] {
    input.request.namespace = "opa"
    input.request.operation = "DELETE"
    msg := sprintf("cannot modify objects in namespace %q", [input.request.namespace])
}

deny[msg] {
    input.request.kind.kind = "ValidatingWebhookConfiguration"
    msg := sprintf("cannot modify validating webhook %q", [input.request.kind.kind])
}

