package pivots

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2021  Seif

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	pb "github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

var SupportedPivotListeners = map[pb.PivotType]CreateListener{
	pb.PivotType_TCP:       CreateTCPPivotListener,
	pb.PivotType_NamedPipe: CreateNamedPipePivotListener,
}
