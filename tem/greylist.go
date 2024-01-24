/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
        "fmt"
)

func (td *TemData) GreylistAdd(name, policy, source string) (string, error) {
     msg := fmt.Sprintf("Domain name \"%s\" added to RPZ source %s with policy %s", name, source, policy)
     return msg, nil
}
