//  Copyright (C) 2020  Éloïs SANCHEZ.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Define the Text Document Traits.

use crate::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Contains a document in full or compact format
pub enum TextDocumentFormat<D: TextDocument> {
    /// Complete format (Allows to check the validity of the signature)
    Complete(D),
    /// Format present in the blocks (does not always allow to verify the signature)
    Compact(D::CompactTextDocument_),
}

impl<D: TextDocument> TextDocumentFormat<D> {
    /// To compact document
    pub fn to_compact_document(&self) -> Cow<D::CompactTextDocument_> {
        match *self {
            TextDocumentFormat::Complete(ref doc) => doc.to_compact_document(),
            TextDocumentFormat::Compact(ref compact_doc) => Cow::Borrowed(compact_doc),
        }
    }
}

/// Trait for a compact text document.
pub trait CompactTextDocument: Sized + Clone + PartialEq {
    /// Generate document compact text.
    /// the compact format is the one used in the blocks.
    ///
    /// - Don't contains leading signatures
    /// - Contains line breaks on all line.
    fn as_compact_text(&self) -> String;
}

impl<D: TextDocument> CompactTextDocument for TextDocumentFormat<D> {
    fn as_compact_text(&self) -> String {
        match *self {
            TextDocumentFormat::Complete(ref doc) => doc.generate_compact_text(),
            TextDocumentFormat::Compact(ref doc) => doc.as_compact_text(),
        }
    }
}

/// Trait for a text document.
pub trait TextDocument: Document {
    /// Type of associated compact document.
    type CompactTextDocument_: CompactTextDocument;

    /// Return document as text without leading signatures.
    fn as_text(&self) -> &str;

    /// Return document as text with leading signatures.
    fn as_text_with_signatures(&self) -> String {
        let mut text = self.as_text().to_string();

        for sig in self.signatures() {
            text.push_str(&sig.to_base64());
            text.push('\n');
        }
        text.pop(); // remove the last line break

        text
    }

    /// Generate compact document.
    /// the compact format is the one used in the blocks.
    /// - Don't contains leading signatures
    fn to_compact_document(&self) -> Cow<Self::CompactTextDocument_>;

    /// Generate document compact text.
    /// the compact format is the one used in the blocks.
    ///
    /// - Don't contains leading signatures
    /// - Contains line breaks on all line.
    fn generate_compact_text(&self) -> String {
        self.to_compact_document().as_compact_text()
    }
}

pub type StringAndSmallVec1<T> = (String, SmallVec<[T; 1]>);

/// Trait for a V10 document builder.
pub trait TextDocumentBuilder {
    /// Type of the builded document.
    type Document: Document;
    /// Type of the signator signing the documents.
    type Signator: Signator<PublicKey = <Self::Document as Document>::PublicKey>;

    /// Generate document text.
    ///
    /// - Don't contains leading signatures
    /// - Contains line breaks on all line.
    fn generate_text(&self) -> String;

    /// Generate final document with signatures, and also return them in an array.
    ///
    /// Returns :
    ///
    /// - Text without signatures
    /// - Signatures
    fn build_signed_text(
        &self,
        signators: Vec<Self::Signator>,
    ) -> StringAndSmallVec1<<<Self::Document as Document>::PublicKey as PublicKey>::Signature> {
        let text = self.generate_text();

        let signatures: SmallVec<_> = {
            let text_bytes = text.as_bytes();
            signators
                .iter()
                .map(|signator| signator.sign(text_bytes))
                .collect()
        };

        (text, signatures)
    }

    /// Build a document with provided text and signatures.
    fn build_with_text_and_sigs(
        self,
        text: String,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> Self::Document;
}

impl<T> DocumentBuilder for T
where
    T: TextDocumentBuilder,
{
    type Document = <Self as TextDocumentBuilder>::Document;
    type Signator = <Self as TextDocumentBuilder>::Signator;

    fn build_and_sign(self, signators: Vec<Self::Signator>) -> Self::Document {
        let (text, signatures) = self.build_signed_text(signators);
        self.build_with_text_and_sigs(text, signatures)
    }

    fn build_with_signature(
        self,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> Self::Document {
        let text = self.generate_text();
        self.build_with_text_and_sigs(text, signatures)
    }
}
