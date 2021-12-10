// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seccomp

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
)

func TestGetSeccompProfileNextName(t *testing.T) {
	// Empty profile list
	profileList := []seccompprofilev1alpha1.SeccompProfile{}
	podName := "podname"
	expectedNextName := "podname"
	nextName := getSeccompProfileNextName(profileList, podName)
	if nextName != expectedNextName {
		t.Fatalf("Invalid computation of next name '%s'. Expecting '%s' from an empty profile list",
			nextName, expectedNextName)
	}

	// There do not exist profiles with podname or podname-X as name.
	profileList = []seccompprofilev1alpha1.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "another-name",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "prefix-podname",
			},
		},
	}
	podName = "podname"
	expectedNextName = "podname"
	nextName = getSeccompProfileNextName(profileList, podName)
	if nextName != expectedNextName {
		t.Fatalf("Invalid computation of next name '%s'. Expecting '%s' from the given profile list",
			nextName, expectedNextName)
	}

	// There exist a profile with the podname but no one with podname-X.
	profileList = []seccompprofilev1alpha1.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "another-name",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "prefix-podname",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname",
			},
		},
	}
	podName = "podname"
	expectedNextName = "podname-2"
	nextName = getSeccompProfileNextName(profileList, podName)
	if nextName != expectedNextName {
		t.Fatalf("Invalid computation of next name '%s'. Expecting '%s' from the given profile list",
			nextName, expectedNextName)
	}

	// There exist a profile with the podname and another with podname-X.
	profileList = []seccompprofilev1alpha1.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "another-name",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "prefix-podname",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname-2",
			},
		},
	}
	podName = "podname"
	expectedNextName = "podname-3"
	nextName = getSeccompProfileNextName(profileList, podName)
	if nextName != expectedNextName {
		t.Fatalf("Invalid computation of next name '%s'. Expecting '%s' from the given profile list",
			nextName, expectedNextName)
	}

	// There exist at least one profile with podname-X.
	profileList = []seccompprofilev1alpha1.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "another-name",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "prefix-podname",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname-10",
			},
		},
	}
	podName = "podname"
	expectedNextName = "podname-11"
	nextName = getSeccompProfileNextName(profileList, podName)
	if nextName != expectedNextName {
		t.Fatalf("Invalid computation of next name '%s'. Expecting '%s' from the given profile list",
			nextName, expectedNextName)
	}

	// There exist multiple profiles with podname-X.
	profileList = []seccompprofilev1alpha1.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "another-name",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "prefix-podname",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname-2",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname-7",
			},
		},
	}
	podName = "podname"
	expectedNextName = "podname-8"
	nextName = getSeccompProfileNextName(profileList, podName)
	if nextName != expectedNextName {
		t.Fatalf("Invalid computation of next name '%s'. Expecting '%s' from the given profile list",
			nextName, expectedNextName)
	}

	// Ignoring profiles with sintax podname-X where X is not a number.
	profileList = []seccompprofilev1alpha1.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "another-name",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname-xa4b5",
			},
		},
	}
	podName = "podname"
	expectedNextName = "podname"
	nextName = getSeccompProfileNextName(profileList, podName)
	if nextName != expectedNextName {
		t.Fatalf("Invalid computation of next name '%s'. Expecting '%s' from the given profile list",
			nextName, expectedNextName)
	}

	// Another case where function must ignore the profiles with
	// syntax podname-X where X is not a number.
	profileList = []seccompprofilev1alpha1.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "another-name",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname-xa4b5",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "podname-5",
			},
		},
	}
	podName = "podname"
	expectedNextName = "podname-6"
	nextName = getSeccompProfileNextName(profileList, podName)
	if nextName != expectedNextName {
		t.Fatalf("Invalid computation of next name '%s'. Expecting '%s' from the given profile list",
			nextName, expectedNextName)
	}
}
