output "rule_group_id" {
  description = "AWS WAF Rule Group which contains all rules for OWASP Top 10 protection."
  value       = "${module.owasp_top_10.rule_group_id}"
}

output "rule_sql_injection_rule_id_01" {
  description = "AWS WAF Rule which mitigates SQL Injection Attacks."
  value       = "${module.owasp_top_10.rule_sql_injection_rule_id_01}"
}

output "rule_auth_token_rule_id_02" {
  description = "AWS WAF Rule which blacklists bad/hijacked JWT tokens or session IDs."
  value       = "${module.owasp_top_10.rule_auth_token_rule_id_02}"
}

output "rule_xss_rule_id_03" {
  description = "AWS WAF Rule which mitigates Cross Site Scripting Attacks."
  value       = "${module.owasp_top_10.rule_xss_rule_id_03}"
}

output "rule_paths_rule_id_04" {
  description = "AWS WAF Rule which mitigates Path Traversal, LFI, RFI."
  value       = "${module.owasp_top_10.rule_paths_rule_id_04}"
}

output "rule_php_insecure_rule_id_06" {
  description = "AWS WAF Rule which mitigates PHP Specific Security Misconfigurations."
  value       = "${module.owasp_top_10.rule_php_insecure_rule_id_06}"
}

output "rule_size_restriction_rule_id_07" {
  description = "AWS WAF Rule which mitigates abnormal requests via size restrictions."
  value       = "${module.owasp_top_10.rule_size_restriction_rule_id_07}"
}

output "rule_csrf_rule_id_08" {
  description = "AWS WAF Rule which enforces the presence of CSRF token in request header."
  value       = "${module.owasp_top_10.rule_csrf_rule_id_08}"
}

output "rule_server_side_include_rule_id_09" {
  description = "AWS WAF Rule which blocks request patterns for webroot objects that shouldn't be directly accessible."
  value       = "${module.owasp_top_10.rule_server_side_include_rule_id_09}"
}
