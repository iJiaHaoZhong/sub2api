#\!/bin/bash
set -e

cd /home/admin/build/sub2api

echo "=== Sub2API Update Script ==="
echo "Current commit: $(git log --oneline -1)"
echo ""

echo "Fetching from upstream (Wei-Shaw/sub2api)..."
git fetch upstream

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse upstream/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "Already up to date with upstream."
    exit 0
fi

# Reset VERSION to avoid merge conflicts
git checkout -- backend/cmd/server/VERSION 2>/dev/null || true

echo "Updates available. Merging upstream/main..."
git merge upstream/main -m "Merge upstream changes"

# Update VERSION from git tag
LATEST_TAG=$(git describe --tags upstream/main 2>/dev/null | cut -d- -f1 || echo "")
if [ -n "$LATEST_TAG" ]; then
    echo "$LATEST_TAG" > backend/cmd/server/VERSION
    git add backend/cmd/server/VERSION
    git commit -m "chore: update VERSION to $LATEST_TAG" 2>/dev/null || true
    echo "Updated VERSION to $LATEST_TAG"
fi

echo "Building with Go..."
cd backend
/usr/local/go/bin/go build -tags embed -o sub2api ./cmd/server

echo "Deploying..."
sudo systemctl stop sub2api
sudo cp sub2api /opt/sub2api/sub2api
sudo systemctl start sub2api

# Clean up to save disk space
rm -f sub2api
/usr/local/go/bin/go clean -cache 2>/dev/null
echo "Build cache cleaned to save disk space."

cd ..
echo "Pushing to origin (your fork)..."
git push origin main

echo ""
echo "=== Update Complete ==="
echo "New commit: $(git log --oneline -1)"
df -h /
systemctl is-active sub2api
