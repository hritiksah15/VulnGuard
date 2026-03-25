#!/bin/bash
# MongoDB Collection Export Script for VulnGuard
# Run this script to export all collections to JSON files

# Get MongoDB URI from environment or use default
MONGO_URI=${MONGO_URI:-"mongodb://localhost:27017/vulnguard"}

# Extract database name from URI
DB_NAME=$(echo $MONGO_URI | sed 's/.*\///' | cut -d'?' -f1)

echo "Exporting MongoDB collections from database: $DB_NAME"
echo "=============================================="

# Create output directory
mkdir -p mongodb_exports

# Export users collection
echo "Exporting users collection..."
mongoexport --uri="$MONGO_URI" --collection=users --out=mongodb_exports/users.json --jsonArray --pretty
if [ $? -eq 0 ]; then
    echo "✓ users.json exported successfully"
else
    echo "✗ Failed to export users collection"
fi

# Export vulnerabilities collection
echo "Exporting vulnerabilities collection..."
mongoexport --uri="$MONGO_URI" --collection=vulnerabilities --out=mongodb_exports/vulnerabilities.json --jsonArray --pretty
if [ $? -eq 0 ]; then
    echo "✓ vulnerabilities.json exported successfully"
else
    echo "✗ Failed to export vulnerabilities collection"
fi

# Export reports collection
echo "Exporting reports collection..."
mongoexport --uri="$MONGO_URI" --collection=reports --out=mongodb_exports/reports.json --jsonArray --pretty
if [ $? -eq 0 ]; then
    echo "✓ reports.json exported successfully"
else
    echo "✗ Failed to export reports collection"
fi

# Export blacklist collection
echo "Exporting blacklist collection..."
mongoexport --uri="$MONGO_URI" --collection=blacklist --out=mongodb_exports/blacklist.json --jsonArray --pretty
if [ $? -eq 0 ]; then
    echo "✓ blacklist.json exported successfully"
else
    echo "✗ Failed to export blacklist collection"
fi

echo ""
echo "Export complete! Files are in mongodb_exports/"
echo "=============================================="
echo "Creating ZIP file..."
cd mongodb_exports && zip -r ../mongodb_collections.zip *.json
if [ $? -eq 0 ]; then
    echo "✓ mongodb_collections.zip created successfully"
else
    echo "✗ Failed to create ZIP file"
fi
