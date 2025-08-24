output "scanner_instance_id" {
  value = aws_instance.scanner_vm.id
}

output "results_bucket_name" {
  value = aws_s3_bucket.results.id
}

output "scanner_vm_public_ip" {
  value = aws_instance.scanner_vm.public_ip
}
