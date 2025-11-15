#!/bin/bash
# setup.sh

echo "🚀 Setting up Raw Wealthy Advanced Backend..."

# Create necessary directories
mkdir -p logs uploads

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Setup environment
if [ ! -f .env ]; then
    echo "🔧 Creating environment file..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your configuration"
fi

# Setup database
echo "🗄️  Setting up database..."
npm run seed

echo "✅ Setup complete!"
echo "🎯 Next steps:"
echo "   1. Edit .env file with your configuration"
echo "   2. Run 'npm run dev' for development"
echo "   3. Run 'npm start' for production"
