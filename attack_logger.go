/*
 *    attack_logger.go - HoneyBadger core library for detecting TCP attacks
 *    such as handshake-hijack, segment veto and sloppy injection.
 *
 *    Copyright (C) 2014  David Stainton
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package HoneyBadger

import (
	"bufio"
	"code.google.com/p/gopacket/tcpassembly"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type AttackReport struct {
	Type          string
	Flow          string
	Time          string
	Payload       string
	Overlap       string
	StartSequence uint32
	EndSequence   uint32
	OverlapStart  int
	OverlapEnd    int
}

type AttackLogger interface {
	ReportHijackAttack(instant time.Time, flow TcpIpFlow)
	ReportInjectionAttack(instant time.Time, flow TcpIpFlow, attemptPayload []byte, overlap []byte, start, end tcpassembly.Sequence, overlapStart, overlapEnd int)
	Close()
}

type AttackJsonLogger struct {
	LogDir    string
	File      *os.File
	BufWriter *bufio.Writer
	Encoder   *json.Encoder
}

func NewAttackJsonLogger(logDir string, flow TcpIpFlow) *AttackJsonLogger {
	var err error
	a := AttackJsonLogger{
		LogDir: logDir,
	}
	a.File, err = os.OpenFile(filepath.Join(a.LogDir, fmt.Sprintf("%s.attackreport.json", &flow)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("error opening file: %v", err))
	}
	a.BufWriter = bufio.NewWriter(a.File)
	a.Encoder = json.NewEncoder(a.BufWriter)
	return &a
}

func (a *AttackJsonLogger) ReportHijackAttack(instant time.Time, flow TcpIpFlow) {
	timeText, err := instant.MarshalText()
	if err != nil {
		panic(err)
	}

	report := &AttackReport{
		Type: "hijack",
		Flow: flow.String(),
		Time: string(timeText),
	}
	a.Publish(report)
}

func (a *AttackJsonLogger) ReportInjectionAttack(instant time.Time, flow TcpIpFlow, attemptPayload []byte, overlap []byte, start, end tcpassembly.Sequence, overlapStart, overlapEnd int) {

	timeText, err := instant.MarshalText()
	if err != nil {
		panic(err)
	}

	report := &AttackReport{
		Type:          "injection",
		Flow:          flow.String(),
		Time:          string(timeText),
		Payload:       base64.StdEncoding.EncodeToString(attemptPayload),
		Overlap:       base64.StdEncoding.EncodeToString(overlap),
		StartSequence: uint32(start),
		EndSequence:   uint32(end),
		OverlapStart:  overlapStart,
		OverlapEnd:    overlapEnd,
	}
	a.Publish(report)
}

func (a *AttackJsonLogger) Publish(report *AttackReport) {
	log.Print("publishing TCP Attack report\n")
	a.Encoder.Encode(*report)
}

func (a *AttackJsonLogger) Close() {
	log.Print("closing attack json logger\n")
	var err error

	err = a.BufWriter.Flush()
	if err != nil {
		panic(err)
	}

	err = a.File.Sync()
	if err != nil {
		panic(err)
	}

	err = a.File.Close()
	if err != nil {
		panic(err)
	}
}
