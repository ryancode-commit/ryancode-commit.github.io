<?php

namespace App\Http\Controllers\API;

use App\Models\Transaction;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\Product;
use App\Models\TransactionItem;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;



class TransactionController extends Controller
{
    public function all(Request $request)
    {
        $id = $request->input('id');
        $limit = $request->input('limit', 6);
        $status = $request->input('status');

        if ($id) {
            $transaction = Transaction::with(['items.product'])->find($id);

            if ($transaction) {
                return ResponseFormatter::success(
                    $transaction,
                    'Data transaksi berhasil diambil'
                );
            } else {
                return ResponseFormatter::error(
                    null,
                    'Data transaksi tidak ada',
                    404
                );
            }
        }

        $transaction =  Transaction::with(['items.product'])->where('users_id', Auth::user()->id);

        if ($status) {
            $transaction->where('status', $status);
        }

        return ResponseFormatter::success(
            $transaction->paginate($limit),
            'Data list transaksi berhasil diambil'
        );
    }

    public function checkout(Request $request)
    {

        // $request->validate([
        //     'name' => ['required', 'string', 'max:255'],
        //     'username' => ['required', 'string', 'max:255', 'unique:users'],
        //     'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
        //     'phone' => ['nullable', 'string', 'max:255'],
        //     'password' => ['required', 'string', new Password],
        // ]);
        $validator = Validator::make($request->all(), [
            'items' => 'required|array',
            'items.*.id' => 'exists:products,id',
            'total_price' => 'required',
            'shipping_price' => 'required',
            'status' => 'required|in:PENDING,SUCCESS,CANCELLED,FAILED,SHIPPING,SHIPPED',
        ]);

        $transaction = Transaction::create([
            'users_id' => Auth::user()->id,
            'address' => $request->address,
            'total_price' => $request->total_price,
            'shipping_price' => $request->shipping_price,
            'status' => $request->status,
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }
        foreach ($request->items as $product) {
            TransactionItem::create([
                'users_id' => Auth::user()->id,
                'products_id' => $product['id'],
                'transactions_id' => $transaction->id,
                'quantity' => $product['quantity']
            ]);
            return ResponseFormatter::success($transaction->load('items.product'), 'Transaksi berhasil');
        }

        return ResponseFormatter::success($transaction->load('items.product'), 'Transaksi berhasil');
    }
}
