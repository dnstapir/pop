/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tapir

import (
//	"github.com/spf13/cobra"
//	"github.com/spf13/viper"
)

type CliFlags struct {
     ShowHdr  bool
     Verbose  bool
     Debug    bool
     UseTLS   bool
     Api      *ApiClient
     PingCount	int
     Zone	string
}

var GlobalCF CliFlags

