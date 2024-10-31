package sudp

import (
	"fmt"
	"time"
)

// Definimos constantes para los niveles de log
const (
	Info  = "sudp - info"
	Error = "sudp - error"
	Warn  = "sudp - warn"
)

// Función para el log
func log(level string, message string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	log := fmt.Sprintf("[%s] [%s]: %s", now, level, message)
	fmt.Println(log)
}
