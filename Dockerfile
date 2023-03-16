# Copyright 2018 The Kubernetes Authors.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM public.ecr.aws/eks-distro/kubernetes/go-runner:v0.13.0-eks-1-23-9
COPY bin/aws-encryption-provider /aws-encryption-provider
ENTRYPOINT ["/go-runner"]
CMD ["/aws-encryption-provider"]