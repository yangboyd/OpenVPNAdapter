//
//  Result.swift
//  OpenVPN Adapter
//
//  Created by Sergey Abramchuk on 16.09.17.
//

import Foundation

enum Result<T, E> {
    case success(T)
    case failure(E)
}
