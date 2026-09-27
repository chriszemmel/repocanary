test:
	npm test

release:
	VERSION=$$(curl -s https://api.github.com/repos/acme/service/releases/latest | jq -r .tag_name); echo $$VERSION
