# frozen_string_literal: true

require 'test_helper'

describe AuthProto do
  it "has a VERSION constant defined" do
    _(AuthProto.const_defined?(:VERSION)).must_equal true
  end
end
