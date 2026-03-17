package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type API struct {
	router          *gin.Engine
	channelsHandler ChannelStatusProvider
	username        string
	password        string
	jwtKey          []byte
	httpServer      *http.Server
	appVersion      string
	frontendPath    string
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type setChannelRequest struct {
	Active bool `json:"active"`
}

// NewAPI creates a new gin REST API instance
func NewAPI(ch ChannelStatusProvider, username, password string, jwtKey []byte, appVersion string, frontendPath string) *API {
	r := gin.Default()

	api := &API{
		router:          r,
		channelsHandler: ch,
		username:        username,
		password:        password,
		jwtKey:          jwtKey,
		appVersion:      appVersion,
		frontendPath:    frontendPath,
	}

	api.setupRoutes()
	return api
}

// Start runs the API server
func (a *API) Start(listenAddress string) error {
	a.httpServer = &http.Server{
		Addr:    listenAddress,
		Handler: a.router,
	}
	return a.httpServer.ListenAndServe()
}

// Stop shuts down the API server gracefully
func (a *API) Stop(ctx context.Context) error {
	if a.httpServer != nil {
		return a.httpServer.Shutdown(ctx)
	}
	return nil
}

func (a *API) setupRoutes() {
	// Enable CORS for all routes (including preflight)
	a.router.Use(CORSMiddleware())

	// Public routes
	a.router.POST("/login", a.login)
	a.router.GET("/api/app-info", a.getAppInfo)

	// Protected routes
	protected := a.router.Group("/api")
	protected.Use(a.authMiddleware())
	{
		protected.GET("/channels", a.getChannels)
		protected.GET("/channels/:id", a.getChannelStatus)
		protected.POST("/channels/:id", a.setChannelStatus)
	}

	// Static files serving and React Router fallback
	if a.frontendPath != "" {
		// Serve index.html on root
		a.router.GET("/", func(c *gin.Context) {
			c.File(fmt.Sprintf("%s/index.html", a.frontendPath))
		})

		// Serve static files (assets, etc.)
		a.router.Static("/assets", fmt.Sprintf("%s/assets", a.frontendPath))
		a.router.StaticFile("/favicon.png", fmt.Sprintf("%s/favicon.png", a.frontendPath))
		a.router.StaticFile("/vite.svg", fmt.Sprintf("%s/vite.svg", a.frontendPath))

		// Fallback for SPA (React Router)
		a.router.NoRoute(func(c *gin.Context) {
			c.File(fmt.Sprintf("%s/index.html", a.frontendPath))
		})
	}
}

func (a *API) login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Username != a.username || req.Password != a.password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create JWT token
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		Subject:   req.Username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(a.jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func (a *API) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return a.jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Subject)
		c.Next()
	}
}

func (a *API) getChannels(c *gin.Context) {
	ports := a.channelsHandler.GetPortIDs()
	// Just return port ids as requested
	c.JSON(http.StatusOK, ports)
}

func (a *API) getChannelStatus(c *gin.Context) {
	channelID := c.Param("id")
	status := a.channelsHandler.GetPort(channelID)

	if status.Error != "" && (status.Error == fmt.Sprintf("port id %s not found", channelID)) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Port not found"})
		return
	}

	c.JSON(http.StatusOK, status)
}

func (a *API) setChannelStatus(c *gin.Context) {
	channelID := c.Param("id")

	var req setChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	err := a.channelsHandler.Set(channelID, req.Active)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to update channel: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "channel": channelID, "active": req.Active})
}
func (a *API) getAppInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version": a.appVersion,
	})
}
