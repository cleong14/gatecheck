package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/format"
)

const HLINE = "\u2500"
const VLINE = "\u2502"

// const ULCORNER = "\u250C"
// const URCORNER = "\u2510"
// const BLCORNER = "\u2514"
// const BRCORNER = "\u2518"

const ULCORNER = "\u256D"
const URCORNER = "\u256E"
const BLCORNER = "\u2570"
const BRCORNER = "\u256F"

func main_sandbox() {
	fmt.Println(ULCORNER + strings.Repeat(HLINE, 4) + URCORNER)
	fmt.Println(VLINE + "Word" + VLINE)
	fmt.Println(BLCORNER + strings.Repeat(HLINE, 4) + BRCORNER)
}

func main() {

	table := format.NewTable()

	table.AppendRow("column 1", "column 2", "column 3 with long header", "column 4", "column 5", "column 6")
	table.AppendRow("value B", "value 3", "value 4", "7", "1.234", "hot")
	table.AppendRow("value A", "value 1", "value 2", "6", "0.214", "warm")
	table.AppendRow("value C", "value 5", "value 6", "8", "3.14159265", "cold")
	table.AppendRow("value D", "value 7", "value 8", "5", "0.00125", "hot")

	format.NewTableWriter(table).WriteTo(os.Stdout)

	table.SetSort(5, format.NewCatagoricLess([]string{"cold", "warm", "hot"}))

	sort.Sort(table)

	new(format.TableWriter).WithCharMap(format.ASCIICharMap).WithTable(table).WriteTo(os.Stdout)
	new(format.TableWriter).WithCharMap(format.PrettyCharMapRoundedCorners).WithTable(table).WriteTo(os.Stdout)
}
