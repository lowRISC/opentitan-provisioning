// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package grpconn implements the gRPC connection utility functions

package auth_service

import (
	"fmt"
	"log"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var lock = &sync.Mutex{}

type AuthController struct {
	enableTLS bool
	userStore *InMemoryUserStore
}

var singleInstance *AuthController

func (ctrl *AuthController) FindUser(userID string) (*User, error) {
	return ctrl.userStore.Find(userID)
}

func (ctrl *AuthController) CreateUser(userID, token, sku string, authMethods []string) (*User, error) {
	user, err := NewUserObject(userID, token, sku, authMethods)
	if err != nil {
		return nil, err
	}
	return user, ctrl.userStore.Save(user)
}

func (ctrl *AuthController) RemoveUser(userID string) (*User, error) {
	log.Printf("In auth_service RemoveUser: recieved user ID =%s", userID)
	user, err := NewUserObject(userID, "", "", []string{})
	if err != nil {
		return nil, err
	}
	return user, ctrl.userStore.Delete(user)
}

func (ctrl *AuthController) AddUser(userID, token, sku string, authMethods []string) (*User, error) {
	user, err := ctrl.FindUser(userID)
	if err == nil {
		fmt.Println("Debug: AddUser: user already exist: ", user)
		user, err = ctrl.RemoveUser(userID)
	}
	return ctrl.CreateUser(userID, token, sku, authMethods)
}

func NewAuthControllerInstance(enableTLS bool) *AuthController {
	if singleInstance == nil {
		lock.Lock()
		defer lock.Unlock()
		if singleInstance == nil {
			fmt.Println("Creating single instance now.")
			singleInstance = &AuthController{
				enableTLS: enableTLS,

				userStore: NewInMemoryUserStore(),
			}
		}
	}
	return singleInstance
}

func GetInstance() (*AuthController, error) {
	if singleInstance == nil {
		return nil, status.Errorf(codes.Internal, "No instance of AuthController")
	}

	return singleInstance, nil
}
