//go:build windows && amd64

package screen

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// Capture takes a screenshot and returns BMP data.
// Uses GDI: CreateDC, CreateCompatibleDC, CreateCompatibleBitmap,
// SelectObject, BitBlt, GetDIBits.
func Capture() ([]byte, error) {
	user32 := syscall.NewLazyDLL("user32.dll")
	gdi32 := syscall.NewLazyDLL("gdi32.dll")

	getDC := user32.NewProc("GetDC")
	releaseDC := user32.NewProc("ReleaseDC")
	getSystemMetrics := user32.NewProc("GetSystemMetrics")
	createCompatibleDC := gdi32.NewProc("CreateCompatibleDC")
	deleteDC := gdi32.NewProc("DeleteDC")
	createCompatibleBitmap := gdi32.NewProc("CreateCompatibleBitmap")
	selectObject := gdi32.NewProc("SelectObject")
	bitBlt := gdi32.NewProc("BitBlt")
	getDIBits := gdi32.NewProc("GetDIBits")
	deleteObject := gdi32.NewProc("DeleteObject")

	// Get screen dimensions
	width, _, _ := getSystemMetrics.Call(0)  // SM_CXSCREEN
	height, _, _ := getSystemMetrics.Call(1) // SM_CYSCREEN

	// Get desktop DC
	hdc, _, _ := getDC.Call(0)
	defer releaseDC.Call(0, hdc)

	// Create compatible DC
	memDC, _, _ := createCompatibleDC.Call(hdc)
	if memDC == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer deleteDC.Call(memDC)

	// Create compatible bitmap
	hBmp, _, _ := createCompatibleBitmap.Call(hdc, width, height)
	if hBmp == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer deleteObject.Call(hBmp)

	// Select bitmap into mem DC
	selectObject.Call(memDC, hBmp)

	// BitBlt: copy screen to memory bitmap
	bitBlt.Call(memDC, 0, 0, width, height, hdc, 0, 0, 0x00CC0020) // SRCCOPY

	// Get bitmap bits
	type BITMAPINFOHEADER struct {
		Size        uint32
		Width       int32
		Height      int32
		Planes      uint16
		BitCount    uint16
		Compression uint32
		SizeImage   uint32
		XPelsPerMeter int32
		YPelsPerMeter int32
		ClrUsed     uint32
		ClrImportant uint32
	}

	bmi := BITMAPINFOHEADER{
		Size:        40,
		Width:       int32(width),
		Height:      -int32(height), // top-down
		Planes:      1,
		BitCount:    24,
		Compression: 0,
	}

	// GetDIBits requires 4-byte aligned row size
	rowSize := (int(width)*3 + 3) &^ 3
	bufSize := rowSize * int(height)
	buf := make([]byte, bufSize)
	getDIBits.Call(memDC, hBmp, 0, uintptr(height),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bmi)), 0)

	// Build BMP file
	imageSize := rowSize * int(height)
	fileSize := 54 + imageSize

	bmp := make([]byte, fileSize)

	// BMP header (14 bytes)
	bmp[0] = 'B'
	bmp[1] = 'M'
	binary.LittleEndian.PutUint32(bmp[2:6], uint32(fileSize))
	binary.LittleEndian.PutUint32(bmp[10:14], 54)

	// DIB header (40 bytes)
	binary.LittleEndian.PutUint32(bmp[14:18], 40)
	binary.LittleEndian.PutUint32(bmp[18:22], uint32(width))
	binary.LittleEndian.PutUint32(bmp[22:26], uint32(height))
	binary.LittleEndian.PutUint16(bmp[26:28], 1)
	binary.LittleEndian.PutUint16(bmp[28:30], 24)
	binary.LittleEndian.PutUint32(bmp[34:38], uint32(imageSize))

	// Copy pixel data (BGR, bottom-up because height is negative)
	for y := int32(0); y < int32(height); y++ {
		srcRow := y * int32(rowSize)
		dstRow := (int32(height) - 1 - y) * int32(rowSize)
		copy(bmp[54+dstRow:], buf[srcRow:srcRow+int32(width)*3])
	}

	return bmp, nil
}
