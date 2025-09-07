# FluxEncrypt Release Notes

## Version 0.1.3 - Current Release

### Major Updates
- **Enhanced Security**: Default RSA key size upgraded to 4096 bits for stronger encryption
- **Python-Compatible CLI**: Added string data encryption via `--data` flag for easier integration
- **Base64 Output**: Default base64 encoded output for text-friendly handling
- **Flexible Output Formats**: Support for both base64 and raw binary output modes

### New CLI Features
- `--data` flag for direct string encryption/decryption
- `--base64` flag for base64 encoded key storage
- `--raw` flag for raw binary output (when not using base64 default)
- Enhanced user experience with better progress indicators and formatting

### API Improvements
- Improved error handling and validation
- Better memory management for large operations
- Enhanced streaming encryption performance
- More comprehensive configuration options

### Security Enhancements
- 4096-bit RSA keys as secure default
- Secure temporary file creation with proper permissions
- Pinned GitHub Actions versions to prevent supply chain attacks
- Enhanced memory protection and zeroization

### Documentation
- Updated all examples to use 4096-bit keys
- Corrected CLI examples to match actual functionality
- Updated version numbers across all documentation
- Improved inline code documentation

### Breaking Changes
- Default RSA key size changed from 2048 to 4096 bits
- CLI output format now defaults to base64 encoding
- Some API signatures may have changed for enhanced security

## Previous Versions

### Version 0.1.0 - Initial Release
- Initial FluxEncrypt implementation
- Hybrid encryption support (RSA-OAEP + AES-GCM)
- Stream processing capabilities
- Command line interface
- Async/await support
- Comprehensive test suite