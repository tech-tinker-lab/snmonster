# Frontend Troubleshooting Guide

## Common Issues and Solutions

### 1. "Could not find a required file. Name: index.js"

**Solution**: The React app needs the main entry point file. This has been fixed by creating:
- `frontend/src/index.tsx` - Main entry point
- `frontend/src/App.tsx` - Main app component
- `frontend/src/TestComponent.tsx` - Simple test component

### 2. Frontend shows blank page

**Check these steps**:

1. **Open Browser Developer Tools** (F12)
   - Check Console tab for errors
   - Check Network tab for failed requests

2. **Verify React is running**:
   ```bash
   cd frontend
   npm start
   ```
   Should show: "Local: http://localhost:3000"

3. **Check if dependencies are installed**:
   ```bash
   cd frontend
   npm install
   ```

4. **Try the simple test component**:
   - The current App.tsx uses a simple TestComponent
   - Should show "🎉 React is Working!" with a test button

### 3. Module not found errors

**Solution**: Reinstall dependencies
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
```

### 4. Port 3001 already in use

**Solution**: 
```bash
# Kill process on port 3001
npx kill-port 3001

# Or use a different port
PORT=3002 npm start
```

### 5. TypeScript errors

**Solution**: Check TypeScript configuration
```bash
cd frontend
npx tsc --noEmit
```

## Quick Fix Commands

### Windows
```cmd
cd frontend
start_dev.bat
```

### Linux/macOS
```bash
cd frontend
npm install
npm start
```

## Testing the Frontend

1. **Start the backend first**:
   ```bash
   python run_backend.py
   ```

2. **Start the frontend**:
   ```bash
   cd frontend
   npm start
   ```

3. **Check these URLs**:
   - Frontend: http://localhost:3001
   - Backend: http://localhost:8001
   - API Docs: http://localhost:8001/docs

## Expected Behavior

### Current Simple Version
- Shows "🎉 React is Working!" message
- Has a test button that shows an alert
- Dark background with white text

### Full Version (when working)
- Network Admin System dashboard
- Device management interface
- Real-time updates
- Professional dark theme

## Debug Steps

1. **Check browser console** (F12 → Console)
2. **Check terminal output** for npm start
3. **Verify file structure**:
   ```
   frontend/
   ├── src/
   │   ├── index.tsx ✅
   │   ├── App.tsx ✅
   │   ├── TestComponent.tsx ✅
   │   └── index.css ✅
   ├── package.json ✅
   └── tsconfig.json ✅
   ```

4. **Test with minimal setup**:
   - Current App.tsx uses only TestComponent
   - No external dependencies except React
   - Should work even if Material-UI fails

## If Still Not Working

1. **Clear browser cache** (Ctrl+Shift+R)
2. **Try different browser**
3. **Check firewall/antivirus** blocking localhost
4. **Restart development server**:
   ```bash
   cd frontend
   npm start
   ```

## Contact Support

If issues persist:
1. Check browser console for specific errors
2. Note the exact error messages
3. Check if backend is running properly
4. Verify Node.js and npm versions 