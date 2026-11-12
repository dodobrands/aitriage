package pathpolicy

import "testing"

func TestIsTestLikeUsesStructuralNames(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"tests/test_security.py",
		"src/auth_test.go",
		"src/auth.spec.ts",
		"testdata/leaked.env",
		"__fixtures__/token.json",
		"__specs__/auth.ts",
		"fixtures/token.json",
		`C:\\repo\\__mocks__\\client.ts`,
		"spec/auth_spec.rb",
		"conftest.py",
		"identity/tests.py",
		"crapi/workshop/tests.py",
	} {
		if !IsTestLike(path) {
			t.Errorf("IsTestLike(%q) = false, want true", path)
		}
	}

	for _, path := range []string{
		"contest.go",
		"src/latest.py",
		"src/testament.ts",
		"src/mockery.go",
		"src/specification.go",
		"production/auth.go",
		"src/routes/tests.ts", // a "tests" resource in an application, not a test module
		"src/contests.py",
	} {
		if IsTestLike(path) {
			t.Errorf("IsTestLike(%q) = true, want false", path)
		}
	}
}
