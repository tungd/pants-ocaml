python_tests(
    name="tests",
    dependencies=[
        ":test_utils",
        "//:pants#pantsbuild.pants.testutil",
    ],
)

python_test_utils(
    name="test_utils",
    sources=["conftest.py"],
    dependencies=["//:pants#pantsbuild.pants.testutil"],
)
