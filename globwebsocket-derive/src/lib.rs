use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_macro_input, DeriveInput, LitStr};

/// Assigns a stable wire name to a typed WebSocket operation.
///
/// ```ignore
/// #[derive(Deserialize, GlobWebsocket)]
/// #[serde(deny_unknown_fields)]
/// #[websocket("projects.create")]
/// struct CreateProject { name: String }
/// ```
#[proc_macro_derive(GlobWebsocket, attributes(websocket))]
pub fn derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let mut operation = None;
    for attr in &input.attrs {
        if attr.path().is_ident("websocket") {
            match attr.parse_args::<LitStr>() {
                Ok(value) => operation = Some(value),
                Err(error) => return error.to_compile_error().into(),
            }
        }
    }
    let Some(operation) = operation else {
        return syn::Error::new_spanned(name, "expected #[websocket(\"operation.name\")]")
            .to_compile_error()
            .into();
    };
    // These are intentionally lightweight payload hints rather than generated
    // JSON Schemas: Serde supports many custom deserialization rules that are
    // not represented in the Rust field type alone. Keeping the declared field
    // names and Rust types still gives callers accurate server-owned guidance.
    let payload_fields = match &input.data {
        syn::Data::Struct(data) => data
            .fields
            .iter()
            .filter_map(|field| {
                field.ident.as_ref().map(|ident| {
                    let field_name = ident.to_string();
                    let field_type = field.ty.to_token_stream().to_string();
                    (field_name, field_type)
                })
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    let payload_fields = payload_fields.iter().map(|(field, ty)| {
        quote! { (#field, #ty) }
    });
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    quote! {
        impl #impl_generics ::globwebsocket::GlobWebsocket for #name #ty_generics #where_clause {
            const NAME: &'static str = #operation;
            fn payload_fields() -> &'static [(&'static str, &'static str)] {
                &[#(#payload_fields),*]
            }
            fn payload_schema() -> Option<::serde_json::Value> {
                ::globwebsocket::trace_payload_schema::<Self>()
            }
        }
    }
    .into()
}
