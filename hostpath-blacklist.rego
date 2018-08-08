package kubernetes.admission

deny[msg] {
    input.request.kind.kind = "PodSecurityPolicy"
    input.request.operation = "CREATE"
    path = input.request.object.spec.allowedHostPaths[_]
    re_match("^/var.*$", path.pathPrefix)
    msg := sprintf("invalid value for hostPath %q", [path])
}
