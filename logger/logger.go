package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

type LogLevel string
type LogType int

// Log levels.
const (
	LOG   LogLevel = "LOG"
	INFO  LogLevel = "INFO"
	ALERT LogLevel = "ALERT"
	ERROR LogLevel = "ERROR"
	FATAL LogLevel = "FATAL"
)

type LogEntry struct {
	Timestamp time.Time
	Level     LogLevel
	LogText   string
}

var logChan = make(chan LogEntry, 1000)
var wg sync.WaitGroup
var globalLogger *log.Logger

func StartLogger() {
	logFile, err := os.OpenFile("combined.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	globalLogger = log.New(logFile, "", 0)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for entry := range logChan {
			globalLogger.Printf("[%s] [%s] %s",
				entry.Timestamp.Format("02-01-2006 15:04:05"),
				entry.Level,
				entry.LogText)
		}
	}()
}

// Log is used for mostly packet log. (Accept or drop)
func Log(level LogLevel, text string) {
	if globalLogger == nil {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		LogText:   text,
	}

	select {
	case logChan <- entry:
	default:
		fmt.Fprintf(os.Stderr, "WARN: log channel full, dropping entry\n")
	}
}

func StopLogger() {
	close(logChan)
	wg.Wait()
}
