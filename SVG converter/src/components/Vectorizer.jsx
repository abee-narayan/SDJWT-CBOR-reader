import React, { useState, useEffect, useRef } from 'react';
import ImageTracer from 'imagetracerjs';
import { UploadCloud, Download, Image as ImageIcon, CheckCircle, AlertTriangle, Settings2, Sparkles, Wand2, Undo2 } from 'lucide-react';

export default function Vectorizer() {
  const [originalImage, setOriginalImage] = useState(null);
  const [originalSize, setOriginalSize] = useState(0);
  const [svgContent, setSvgContent] = useState('');
  const [svgSize, setSvgSize] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isAutoOptimizing, setIsAutoOptimizing] = useState(false);
  const [previousSettings, setPreviousSettings] = useState(null);
  
  // Settings state
  const [colors, setColors] = useState(8);
  const [tolerance, setTolerance] = useState(2.0); // 0.1 to 10.0
  const [blur, setBlur] = useState(1); // 0 to 5
  const [precision, setPrecision] = useState(1); // 0 to 3
  const [pathOmit, setPathOmit] = useState(20); // 0 to 100

  const fileInputRef = useRef(null);
  const imgRef = useRef(null);

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    setOriginalSize(file.size);
    const reader = new FileReader();
    reader.onload = (event) => {
      // DOWNSCALE IMAGE BEFORE TRACING TO PREVENT HUGE SVG SIZES
      const img = new Image();
      img.onload = () => {
        // We set max width/height to 400px. This aggressively removes JPG artifacts
        // and guarantees a much lower path count when traced.
        const MAX_DIM = 400;
        let width = img.width;
        let height = img.height;
        
        if (width > MAX_DIM || height > MAX_DIM) {
          if (width > height) {
            height *= MAX_DIM / width;
            width = MAX_DIM;
          } else {
            width *= MAX_DIM / height;
            height = MAX_DIM;
          }
        }
        
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, width, height);
        
        const resizedDataUrl = canvas.toDataURL('image/png');
        setOriginalImage(resizedDataUrl);
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  };

  const processImage = () => {
    if (!originalImage || !imgRef.current) return;
    setIsProcessing(true);
    
    setTimeout(() => {
      try {
        // ImageTracer options mapping
        const options = {
          colorsampling: 2,
          numberofcolors: colors,
          mincolorratio: 0,
          colorquantcycles: 3,
          ltres: tolerance, // Line threshold (higher = simpler)
          qtres: tolerance, // Quadratic curve threshold
          pathomit: pathOmit, // Discard tiny noise paths
          rightangleenhance: true,
          scale: 1,
          roundcoords: precision,
          blurradius: blur,
          blurdelta: 20,
          strokewidth: 0,
          linefilter: true,
          desc: false,
          viewbox: true
        };

        // Trace the image asynchronously
        ImageTracer.imageToSVG(originalImage, (svgStr) => {
          try {
            // Post-process the SVG to make it smaller
            let optimizedSvg = svgStr
              .replace(/<\?xml.*?\?>/, '') // Remove xml declaration
              .replace(/<!--.*?-->/s, '') // Remove comments
              .replace(/\s+/g, ' ') // Minify whitespace
              .replace(/>\s+</g, '><') // Remove space between tags
              .trim();
            
            setSvgContent(optimizedSvg);
            
            const blob = new Blob([optimizedSvg], { type: 'image/svg+xml' });
            setSvgSize(blob.size);
          } catch (e) {
            console.error("Post-processing failed:", e);
          } finally {
            setIsProcessing(false);
          }
        }, options);
      } catch (err) {
        console.error("Vectorization failed:", err);
        setIsProcessing(false);
      }
    }, 50);
  };

  // Auto Optimize function that attempts to enforce <10KB rule
  const handleAutoOptimize = () => {
    if (!originalImage) return;
    setIsAutoOptimizing(true);
    
    // Save current settings to allow reverting
    setPreviousSettings({
      colors, tolerance, blur, pathOmit, precision
    });
    
    // Aggressive optimization settings
    setColors(4);
    setTolerance(5.0);
    setBlur(2);
    setPathOmit(50);
    setPrecision(0); // 0 decimal places drops the file size enormously
    
    setTimeout(() => {
      setIsAutoOptimizing(false);
    }, 800);
  };

  const handleRevert = () => {
    if (!previousSettings) return;
    setColors(previousSettings.colors);
    setTolerance(previousSettings.tolerance);
    setBlur(previousSettings.blur);
    setPathOmit(previousSettings.pathOmit);
    setPrecision(previousSettings.precision);
    setPreviousSettings(null);
  };

  useEffect(() => {
    if (originalImage) {
      processImage();
    }
  }, [originalImage, colors, tolerance, blur, precision, pathOmit]);

  const handleDownload = () => {
    if (!svgContent) return;
    const blob = new Blob([svgContent], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vectorized-logo.svg';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const formatSize = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    return (bytes / k).toFixed(2) + ' KB';
  };

  const isOptimal = svgSize > 0 && svgSize < 10240; // less than 10KB
  
  return (
    <div className="main-content">
      <div className="sidebar glass-panel animate-fade-in">
        <div 
          className="upload-area"
          onClick={() => fileInputRef.current?.click()}
        >
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileUpload} 
            accept="image/png, image/jpeg, image/jpg" 
            style={{ display: 'none' }} 
          />
          <UploadCloud className="upload-icon" />
          <h3>Upload Logo</h3>
          <p className="help-text">Drop your PNG or JPG here</p>
        </div>

        {originalImage && (
          <div className="settings-panel">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Settings2 size={18} color="var(--primary)" />
                <h3 style={{ fontSize: '1.1rem' }}>Settings</h3>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                {previousSettings && (
                  <button 
                    className="button button-outline" 
                    style={{ padding: '4px 12px', fontSize: '0.8rem', borderColor: 'var(--text-muted)' }}
                    onClick={handleRevert}
                    disabled={isAutoOptimizing || isProcessing}
                    title="Revert to previous settings"
                  >
                    <Undo2 size={14} />
                    Revert
                  </button>
                )}
                <button 
                  className="button button-outline" 
                  style={{ padding: '4px 12px', fontSize: '0.8rem' }}
                  onClick={handleAutoOptimize}
                  disabled={isAutoOptimizing || isProcessing}
                >
                  <Wand2 size={14} />
                  Auto <span style={{color: 'var(--success)', marginLeft: '4px'}}>10KB Limit</span>
                </button>
              </div>
            </div>
            
            <div className="setting-group">
              <div className="setting-header">
                <label>Color Palette Size</label>
                <span className="setting-value">{colors}</span>
              </div>
              <input 
                type="range" 
                min="2" max="32" step="1" 
                value={colors} 
                onChange={(e) => setColors(Number(e.target.value))} 
              />
            </div>

            <div className="setting-group">
              <div className="setting-header">
                <label>Path Simplification (ltres/qtres)</label>
                <span className="setting-value">{tolerance.toFixed(1)}</span>
              </div>
              <input 
                type="range" 
                min="0.1" max="10.0" step="0.1" 
                value={tolerance} 
                onChange={(e) => setTolerance(Number(e.target.value))} 
              />
            </div>
            
            <div className="setting-group">
              <div className="setting-header">
                <label>Noise/Artifact Filter (pathOmit)</label>
                <span className="setting-value">{pathOmit}</span>
              </div>
              <input 
                type="range" 
                min="0" max="100" step="5" 
                value={pathOmit} 
                onChange={(e) => setPathOmit(Number(e.target.value))} 
              />
            </div>

            <div className="setting-group">
              <div className="setting-header">
                <label>Pre-Blur (Artifact smoothing)</label>
                <span className="setting-value">{blur}</span>
              </div>
              <input 
                type="range" 
                min="0" max="5" step="1" 
                value={blur} 
                onChange={(e) => setBlur(Number(e.target.value))} 
              />
            </div>
            
            <div className="setting-group">
              <div className="setting-header">
                <label>Decimal Precision</label>
                <span className="setting-value">{precision}</span>
              </div>
              <input 
                type="range" 
                min="0" max="3" step="1" 
                value={precision} 
                onChange={(e) => setPrecision(Number(e.target.value))} 
              />
            </div>
          </div>
        )}
      </div>

      <div className="preview-area">
        {!originalImage ? (
          <div className="glass-panel empty-state animate-fade-in" style={{ animationDelay: '0.1s' }}>
            <Sparkles size={48} color="var(--primary)" style={{ marginBottom: '16px', opacity: 0.8 }} />
            <h2>No Image Selected</h2>
            <p>Upload a raster logo to begin vectorizing</p>
          </div>
        ) : (
          <div className="preview-cards glass-panel animate-fade-in">
            <div className="preview-card">
              <div className="preview-header">
                <span className="preview-title">Original Raster</span>
                <span className="badge badge-warning">{formatSize(originalSize)}</span>
              </div>
              <div className="image-container">
                <img 
                  ref={imgRef}
                  src={originalImage} 
                  alt="Original" 
                />
              </div>
            </div>

            <div className="preview-card">
              <div className="preview-header">
                <span className="preview-title">Vector SVG</span>
                {svgSize > 0 && (
                  <span className={`badge ${isOptimal ? 'badge-success' : 'badge-danger'}`}>
                    {formatSize(svgSize)}
                  </span>
                )}
              </div>
              <div className="image-container">
                {isProcessing || isAutoOptimizing ? (
                  <div className="loader"></div>
                ) : svgContent ? (
                  <div dangerouslySetInnerHTML={{ __html: svgContent }} style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }} />
                ) : null}
              </div>
            </div>
          </div>
        )}

        {originalImage && (
          <div className="glass-panel action-bar animate-fade-in" style={{ animationDelay: '0.2s' }}>
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '8px' }}>
              {isOptimal ? (
                <>
                  <CheckCircle size={20} color="var(--success)" />
                  <span style={{ color: 'var(--success)', fontWeight: 500 }}>Ready for API! (Under 10KB)</span>
                </>
              ) : (
                <>
                  <AlertTriangle size={20} color="var(--danger)" />
                  <span style={{ color: 'var(--danger)', fontWeight: 500 }}>Over 10KB. Click the "Auto 10KB Limit" wand to crush the size!</span>
                </>
              )}
            </div>
            
            <button 
              className="button button-accent" 
              onClick={handleDownload}
              disabled={isProcessing || isAutoOptimizing || !svgContent}
            >
              <Download size={18} />
              Download SVG
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
