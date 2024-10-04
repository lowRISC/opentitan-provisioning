// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
//// Package grpconn implements the gRPC connection utility functions

package auth_service

import (
	"context"
	"log"
	"strings"

	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthInterceptor struct {
	enableTLS      bool
	excludeMethods []string
}

func NewAuthInterceptor(enableTLS bool) *AuthInterceptor {
	return &AuthInterceptor{enableTLS, excludeMethodsList()}
}

func excludeMethodsList() []string {
	return []string{"InitSession", "CloseSession"}
}

func getClientIP(ctx context.Context) string {
	clientIP, _ := grpconn.ExtractClientIP(ctx)
	return clientIP
}

func GetUserID(ctx context.Context, md metadata.MD) string {
	userID := getClientIP(ctx)
	clientProvidedUserID := md["user_id"]
	if clientProvidedUserID != nil {
		userID = clientProvidedUserID[0]
	}
	return userID
}

// Unary returns a server interceptor function to authenticate and authorize unary RPC
func (interceptor *AuthInterceptor) Unary(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	log.Println("--> unary interceptor: ", info.FullMethod)

	err := interceptor.authorize(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}

	if interceptor.enableTLS {
		// Check if the IP or DNS name match and if they do then proceed with the next handler
		return grpconn.CheckEndpointInterceptor(ctx, req, info, handler)
	}
	// No need to check if the IP or DNS name match, proceed with the next handler
	return handler(ctx, req)

}

// contains checks if a string has a sub string as a surffix
func hasSuffix(str_in string, str_list []string) (string, bool) {
	for _, str := range str_list {
		if strings.HasSuffix(str_in, str) {
			return str, true
		}
	}
	return "", false
}

func (interceptor *AuthInterceptor) authorize(ctx context.Context, method string) error {
	// Check if the method is accessible without authorization.
	exclude_method, ok := hasSuffix(method, interceptor.excludeMethods)
	if ok {
		log.Printf("exit authorize, method = %v", exclude_method)
		return nil
	}

	// Get authorization controller for the PA.
	auth_controller, err := GetInstance()
	if err != nil {
		log.Printf("session is not initialized: %v", err)
		return status.Errorf(codes.Internal, "session is not initialized: %v", err)
	}

	// Get context metadata.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Printf("metadata is not provided")
		return status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	// Extract userID and lookup in memory store.
	// If userID is not provided, use the host IP address as the userID.
	userID := GetUserID(ctx, md)
	user, err := auth_controller.FindUser(userID)
	if err != nil {
		log.Printf("user not found (user, err): %v , %v", user, err)
		return status.Errorf(codes.Internal, "user not found (user, err): %v , %v", user, err)
	}

	// Extract authorization token and validate it.
	values := md["authorization"]
	if len(values) == 0 {
		log.Printf("authorization token is not provided")
		return status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}
	accessToken := values[0]
	if user.sessionToken != accessToken {
		log.Printf("incorrect access token")
		return status.Errorf(codes.NotFound, "incorrect access token")
	}

	// Validate RPC function is accessible after authorization.
	for _, accessible_method := range user.authMethods {
		if strings.HasSuffix(method, accessible_method) {
			log.Printf("exit authorize, method = %v", method)
			return nil
		}
	}

	log.Printf("no permission to access this method: %v", method)
	return status.Error(codes.PermissionDenied, "no permission to access this method")
}
