output "rule_group_id" {
  description = "AWS WAF Rule Group which contains all rules for OWASP Top 10 protection."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule_group.owasp_top_10.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule_group.owasp_top_10.*.id, list("NOT_CREATED")), "0")}"
}

output "rule_sql_injection_rule_id_01" {
  description = "AWS WAF Rule which mitigates SQL Injection Attacks."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule.owasp_sql_injection_rule_01.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule.owasp_sql_injection_rule_01.*.id, list("NOT_CREATED")), "0")}"
}

output "rule_auth_token_rule_id_02" {
  description = "AWS WAF Rule which blacklists bad/hijacked JWT tokens or session IDs."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule.owasp_auth_token_rule_02.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule.owasp_auth_token_rule_02.*.id, list("NOT_CREATED")), "0")}"
}

output "rule_xss_rule_id_03" {
  description = "AWS WAF Rule which mitigates Cross Site Scripting Attacks."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule.owasp_xss_rule_03.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule.owasp_xss_rule_03.*.id, list("NOT_CREATED")), "0")}"
}

output "rule_paths_rule_id_04" {
  description = "AWS WAF Rule which mitigates Path Traversal, LFI, RFI."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule.owasp_paths_rule_04.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule.owasp_paths_rule_04.*.id, list("NOT_CREATED")), "0")}"
}

output "rule_php_insecure_rule_id_06" {
  description = "AWS WAF Rule which mitigates PHP Specific Security Misconfigurations."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule.owasp_php_insecure_rule_06.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule.owasp_php_insecure_rule_06.*.id, list("NOT_CREATED")), "0")}"
}

output "rule_size_restriction_rule_id_07" {
  description = "AWS WAF Rule which mitigates abnormal requests via size restrictions."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule.owasp_size_restriction_rule_07.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule.owasp_size_restriction_rule_07.*.id, list("NOT_CREATED")), "0")}"
}

output "rule_csrf_rule_id_08" {
  description = "AWS WAF Rule which enforces the presence of CSRF token in request header."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule.owasp_csrf_rule_08.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule.owasp_csrf_rule_08.*.id, list("NOT_CREATED")), "0")}"
}

output "rule_server_side_include_rule_id_09" {
  description = "AWS WAF Rule which blocks request patterns for webroot objects that shouldn't be directly accessible."
  value       = "${lower(var.target_scope) == "regional" ? element(concat(aws_wafregional_rule.owasp_server_side_include_rule_09.*.id, list("NOT_CREATED")), "0") : element(concat(aws_waf_rule.owasp_server_side_include_rule_09.*.id, list("NOT_CREATED")), "0")}"
}
