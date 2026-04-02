// Copyright 2012-2017 Docker, Inc.
// Copyright 2026 The Inspektor Gadget authors
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

// This file is derived from github.com/moby/moby/pkg/namesgenerator
// (https://github.com/moby/moby/blob/v28.1.1/pkg/namesgenerator/names-generator.go)
// and has been modified for use in Inspektor Gadget.

// Package namesgenerator generates random names using adjective-noun pairs.
package namesgenerator

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
)

var (
	left = [...]string{
		"admiring", "adoring", "affectionate", "agitated", "amazing",
		"angry", "awesome", "beautiful", "blissful", "bold",
		"boring", "brave", "busy", "charming", "clever",
		"compassionate", "competent", "condescending", "confident", "cool",
		"cranky", "crazy", "dazzling", "determined", "distracted",
		"dreamy", "eager", "ecstatic", "elastic", "elated",
		"elegant", "eloquent", "epic", "exciting", "fervent",
		"festive", "flamboyant", "focused", "friendly", "frosty",
		"funny", "gallant", "gifted", "goofy", "gracious",
		"great", "happy", "hardcore", "heuristic", "hopeful",
		"hungry", "infallible", "inspiring", "intelligent", "interesting",
		"jolly", "jovial", "keen", "kind", "laughing",
		"loving", "lucid", "magical", "modest", "musing",
		"mystifying", "naughty", "nervous", "nice", "nifty",
		"nostalgic", "objective", "optimistic", "peaceful", "pedantic",
		"pensive", "practical", "priceless", "quirky", "quizzical",
		"recursing", "relaxed", "reverent", "romantic", "sad",
		"serene", "sharp", "silly", "sleepy", "stoic",
		"strange", "stupefied", "suspicious", "sweet", "tender",
		"thirsty", "trusting", "unruffled", "upbeat", "vibrant",
		"vigilant", "vigorous", "wizardly", "wonderful", "xenodochial",
		"youthful", "zealous", "zen",
	}

	right = [...]string{
		"agnesi", "albattani", "allen", "almeida", "antonelli",
		"archimedes", "ardinghelli", "aryabhata", "austin", "babbage",
		"banach", "banzai", "bardeen", "bartik", "bassi",
		"beaver", "bell", "benz", "bhabha", "bhaskara",
		"blackburn", "blackwell", "bohr", "booth", "borg",
		"bose", "bouman", "boyd", "brahmagupta", "brattain",
		"brown", "buck", "burnell", "cannon", "carson",
		"cartwright", "carver", "cerf", "chandrasekhar", "chaplygin",
		"chatelet", "chatterjee", "chebyshev", "cohen", "chaum",
		"clarke", "colden", "cori", "cray", "curran",
		"curie", "darwin", "davinci", "dewdney", "dhawan",
		"diffie", "dijkstra", "dirac", "driscoll", "dubinsky",
		"easley", "edison", "einstein", "elbakyan", "elgamal",
		"elion", "ellis", "engelbart", "euclid", "euler",
		"faraday", "feistel", "fermat", "fermi", "feynman",
		"franklin", "gagarin", "galileo", "galois", "ganguly",
		"gates", "gauss", "germain", "goldberg", "goldstine",
		"goldwasser", "golick", "goodall", "gould", "greider",
		"grothendieck", "haibt", "hamilton", "haslett", "hawking",
		"heisenberg", "hellman", "hermann", "herschel", "hertz",
		"heyrovsky", "hodgkin", "hofstadter", "hoover", "hopper",
		"hugle", "hypatia", "ishizaka", "jackson", "jang",
		"jemison", "jennings", "jepsen", "johnson", "joliot",
		"jones", "kalam", "kapitsa", "kare", "keldysh",
		"keller", "kepler", "khayyam", "khorana", "kilby",
		"kirch", "knuth", "kowalevski", "lalande", "lamarr",
		"lamport", "leakey", "leavitt", "lederberg", "lehmann",
		"lewin", "lichterman", "liskov", "lovelace", "lumiere",
		"mahavira", "margulis", "matsumoto", "maxwell", "mayer",
		"mccarthy", "mcclintock", "mclaren", "mclean", "mcnulty",
		"meitner", "mendel", "mendeleev", "meninsky", "merkle",
		"mestorf", "mirzakhani", "montalcini", "moore", "morse",
		"murdock", "moser", "napier", "nash", "neumann",
		"newton", "nightingale", "nobel", "noether", "northcutt",
		"noyce", "panini", "pare", "pascal", "pasteur",
		"payne", "perlman", "pike", "poincare", "poitras",
		"proskuriakova", "ptolemy", "raman", "ramanujan", "ride",
		"ritchie", "rhodes", "robinson", "roentgen", "rosalind",
		"rubin", "saha", "sammet", "sanderson", "satoshi",
		"shamir", "shannon", "shaw", "shirley", "shockley",
		"shtern", "sinoussi", "snyder", "solomon", "spence",
		"stonebraker", "sutherland", "swanson", "swartz", "swirles",
		"taussig", "tesla", "tharp", "thompson", "torvalds",
		"tu", "turing", "varahamihira", "vaughan", "villani",
		"visvesvaraya", "volhard", "wescoff", "wilbur", "wiles",
		"williams", "williamson", "wilson", "wing", "wozniak",
		"wright", "wu", "yalow", "yonath", "zhukovsky",
	}
)

func randIntn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand.Int failed: %v", err))
	}
	return int(v.Int64())
}

// GetRandomName generates a random name from the list of adjectives and surnames
// formatted as "adjective_surname". For example 'focused_turing'. If retry is non-zero,
// a random integer between 0 and 10 will be added to the end of the name.
func GetRandomName(retry int) string {
begin:
	name := left[randIntn(len(left))] + "_" + right[randIntn(len(right))]
	if name == "boring_wozniak" /* Steve Wozniak is not boring */ {
		goto begin
	}

	if retry > 0 {
		name += strconv.Itoa(randIntn(10))
	}
	return name
}
